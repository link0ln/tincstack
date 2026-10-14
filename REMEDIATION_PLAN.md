# План исправлений и архитектурной переработки `tincstack` (Remediation & Single-Port / Single-Flow Plan)

Этот файл фиксирует все выявленные в ходе ревью проблемы (C-ядро, сетевой стек, транспорты, конфигуратор, клиенты Windows / Android / Docker), а также архитектурное требование по объединению мета-соединения и трафика данных в единый порт/поток выбранного протокола.

Статусы задач:
- `[ ]` — Ожидает выполнения
- `[/]` — В работе
- `[x]` — Выполнено и проверено

---

## Архитектурное требование: Единый порт и единый поток для метаданных и трафика (Single-Port / Single-Flow Architecture)

**Проблема (наследие ванильного `tinc` и наслоения портов):**
1. В ванильном `tinc` мета-соединение устанавливается по TCP (порт `655`), а данные пытаются идти отдельно по UDP (порт `655`, либо через `EDGE`-порт, переданный в `ADD_EDGE`).
2. При добавлении транспортов `https`, `quic`, `obfs` появились дополнительные порты (`HttpsPort = 443`, `QuicPort = 443`, `ObfsPort = ...`), существующие параллельно с `Port = 655`. В результате:
   - Мета-соединение поднимается по одному порту (например, `443` или `8444`), но `ADD_EDGE` / `UDP_INFO` / `send_carrier_beacon()` / `choose_udp_address()` продолжают анонсировать и пробивать отдельный UDP-порт `655` (`myport.udp` / `listen_socket`).
   - Трафик и пробники пытаются идти в обход выбранного протокола и его порта по отдельному UDP-порту `655`.

**Целевая архитектура:**
1. **Весь трафик (метаданные, управление, ключи SPTPS, пробники MTU и полезный VPN-трафик) обязан идти по одному и тому же порту и внутри выбранного протокола (транспорта):**
   - **`quic`**: метаданные (QUIC stream) + данные (QUIC DATAGRAM / stream fallback) идут строго внутри одного QUIC-соединения и одного UDP-порта. Никаких побочных UDP-пробников (`send_carrier_beacon` / `try_udp`) мимо QUIC-потока на другой порт.
   - **`https`**: метаданные + данные идут строго внутри одного TLS 1.3 TCP-соединения и одного TCP-порта. Никаких побочных UDP-пробников на отдельный UDP-порт.
   - **`obfs`**: метаданные (single-flow `sf` поверх `obfs`) + данные (`SPTPS` поверх `obfs`) идут строго по одному и тому же UDP-сокету и адресу/порту (`c->address`), на котором установлено соединение `obfs`.
   - **`sf`**: метаданные (single-flow `sf`) + данные (`SPTPS`) идут строго по одному и тому же UDP-сокету и адресу/порту (`c->address`), на котором установлено соединение `sf`.
   - **`plain`**: использует основной порт узла (`Port`).
2. **Единый порт по умолчанию для всех протоколов (Unified Port Mux):**
   - Входящий диспетчер `listen_socket[]` уже умеет мультиплексировать на **одном** порту:
     - На TCP (`transport_front_dispatch`): TLS 1.3 (`https` + decoy web server), HTTP decoy и `plain`.
     - На UDP (`transport_udp_dispatch`): `quic` (RFC 9000 + HTTP/3 decoy), `obfs`, `sf` и `SPTPS`.
   - Если `HttpsPort`, `QuicPort`, `ObfsPort` явно не заданы (или совпадают с `Port`), все протоколы работают через **один единый порт узла (`Port`)** без открытия лишних сокетов.
   - Если же для конкретного протокола задан свой порт (`HttpsPort`, `QuicPort`, `ObfsPort`), то при выборе этого протокола **и метаданные, и трафик данных** идут исключительно через порт этого протокола, без разделения на «порт мета-коннекшена» и «порт трафика».

---

## Фаза 1: Критические исправления C-ядра (`core/tincd/src/`)

- [x] **1.1. Исправление `address_cache.c` (бесконечный цикл в `get_recent_address()` и отказ multi-Address / `UdpMetaFallback` / смены транспорта)**
  - **Файл:** `core/tincd/src/address_cache.c` (строки 156–188)
  - **Детали:** Перенести `cache->cfg = lookup_config(cache->config_tree, "Address");` внутрь блока `if(!cache->config_tree)`. Исправить обход `lg_tried` для всех `Address` хоста, а не только первого.

- [x] **1.2. Исправление Use-After-Free и разделения `outgoing_t` в `protocol_auth.c` (`ack_h`)**
  - **Файл:** `core/tincd/src/protocol_auth.c` (строки 1208–1270)
  - **Детали:** В `ack_h()` при срабатывании `transport_outranks_connection(c->outgoing, c)` отцеплять `outgoing_t *out = c->outgoing; c->outgoing = NULL;` перед вызовом `retry_outgoing(out);`, чтобы `c1` и новое исходящее соединение `c2` никогда не владели одним `outgoing_t` одновременно.

- [x] **1.3. Устранение UB вычитания указателей `ls - listen_socket` и выхода за границы массива при `ObfsPort`**
  - **Файлы:** `core/tincd/src/obfs.c` (строки 1268–1279), `core/tincd/src/transport_sf.c` (строки 529, 633), `core/tincd/src/net_packet.c` (строка 2445)
  - **Детали:** Гарантировать, что `obfs_inject()` и любые обработчики пакетов всегда передают валидный указатель из `listen_socket[]` (fallback на `&listen_socket[0]`, если `sa_family` отличается из-за dual-stack) и проверять границы индекса `ls - listen_socket`.

- [x] **1.4. Изоляция портов при dial (`https_dial`, `quic_dial`, `obfs_dial`, `sf_dial`) и защита `address_cache` от отравления портами**
  - **Файлы:** `core/tincd/src/https.c` (строки 755–775), `core/tincd/src/transport_quic.c` (строки 1635–1655), `core/tincd/src/obfs.c` (строки 1575–1600), `core/tincd/src/protocol_misc.c` (строки 63–76)
  - **Детали:**
    - Не подставлять локальные `https_port_option` / `quic_port_option` / `obfs_port_option` / `myport.udp` вместо порта удалённого пира, если у пира в конфиге не задан соответствующий `*Port`.
    - Не затирать порт в `obfs_dial(c)`, если соединение инициировано через `UdpMetaFallback` (по уже подтверждённому адресу потока).
    - Не перезаписывать базовый порт в `address_cache` специфичным портом транспорта при `pong_h()`, либо резолвить порт транспорта поверх базового адреса только на время dial.

- [x] **1.5. Переработка тракта данных и метаданных в единый порт/поток выбранного протокола (`net_packet.c`, `transport.c`, `obfs.c`, `transport_sf.c`, `transport_quic.c`, `https.c`, `protocol_edge.c`)**
  - **Файлы:** `core/tincd/src/net_packet.c`, `core/tincd/src/transport.c`, `core/tincd/src/obfs.c`, `core/tincd/src/transport_sf.c`, `core/tincd/src/protocol_edge.c`
  - **Детали:**
    - При активном соединении с соседом через выбранный протокол (`quic`, `https`, `obfs`, `sf`) весь трафик данных и пробники к этому соседу должны идти через **тот же самый порт и транспортный поток**, что и мета-соединение (`c->address` и сокет данного транспорта), а не через отдельный порт `655`.
    - Отключить `send_carrier_beacon()` и сторонние UDP-пробники на отдельный порт, когда соединение работает через `quic` или `https`.
    - Для `obfs` и `sf`: синхронизировать адрес/порт данных (`n->address` / `edge->address`) с адресом/портом установленного single-flow соединения (`c->address`) и отправлять пакеты через тот же сокет (`sf_local_address` / `obfs_pick_socket`), с которого установлено соединение.
    - Привести логику `transport_front_port()` к единому порту: если отдельный `HttpsPort`/`QuicPort`/`ObfsPort` не задан (или совпадает с `Port`), мультиплексировать все протоколы на основном `Port` (`listen_socket[]`).

- [x] **1.6. Полное исправление `dnsrefresh.c` (Windows Winsock, потокобезопасность, multi-Address, очистка стейта и памяти)**
  - **Файл:** `core/tincd/src/dnsrefresh.c`
  - **Детали:**
    - На Windows (`HAVE_WINDOWS`) связать `sock` и `peer` взаимным `connect()` и использовать `send()`, `recv()`, `closesocket()` вместо CRT `write()`, `read()`, `close()`.
    - Убрать вызов `logger()` из фонового `pthread` (`dnsrefresh_thread`), перенеся логирование ошибок резолвинга в главный поток (`dnsrefresh_io_cb`).
    - Сохранять в `dnsrefresh_result_t` все разрешённые IP-адреса (`addrinfo`), а в `dnsrefresh_apply()` не разрывать активное соединение `n->connection`, если его текущий IP совпадает хотя бы с одним из разрешённых `Address` этого узла.
    - При `dnsrefresh_rebuild()` удалять устаревшие задачи (удалённые узлы/хостнеймы), обновлять изменившийся порт, освобождать старый `dnsrefresh.pending` в `dnsrefresh_queue_batch()`, освобождать очереди в `dnsrefresh_exit()` и сбрасывать `dnsrefresh.stop = false`.

- [x] **1.7. Исправление burst-паддинга (`obfs_pad_next_burst` / `https_pad_next_burst`), PMTU-блэкхола и `DirectSeal` состояний**
  - **Файлы:** `core/tincd/src/obfs.c` (строки 543–579, 914–947, 1142–1166, 1415–1450), `core/tincd/src/net_packet.c` (строки 156–194, 792–836), `core/tincd/src/https.c` (строки 100–125, 697–740)
  - **Детали:**
    - Ограничить `obfs_link_budget()` при `pad_burst` значением открытого туннельного `n->minmtu` (если `n->minmtu > 0`), чтобы паддинг TLS ClientHello никогда не превышал реальный PMTU пути.
    - Не зажимать исходящие PMTU-пробы до 1190 байт, пока `l->have_addr == false` (использовать адрес получателя `sa` для расчёта бюджета).
    - Вызывать `is_tls_client_hello()` в `send_sptps_packet()` **до** `compress_packet()` и всегда пропускать 14 байт Ethernet-заголовка (включая `RMODE_SWITCH` / `RMODE_HUB`, проверив EtherType `0x0800` / `0x86DD`).
    - В `obfs_udp_try()` на fast-path при неудаче `obfs_open()` не делать немедленный `return false;`, а продолжать поиск / переходить к cold scan; сбрасывать `l->active` при закрытии/смене сессии, чтобы не обходить `dseal_verdict()`.
    - В `https` выставлять `pad_budget` непосредственно перед отправкой тела `PACKET`, чтобы 7-байтовый заголовок не съедал паддинг.

- [x] **1.8. Защита QUIC / Web Front от DoS 64 UDP-пакетами и коллизий DCID + атомарный `tls_reload_cert()`**
  - **Файлы:** `core/tincd/src/decoy.c` (строки 2539–2549), `core/tincd/src/transport_quic.c` (строки 262–272, 1656–1768, 1871–1903), `core/tincd/src/tls.c` (строки 510–525, 638–649, 698–742)
  - **Детали:**
    - Разделить квоту неаутентифицированных UDP QUIC Initial-сессий и TCP `https` подключений (или вытеснять старейшие неаутентифицированные QUIC-сессии в состоянии handshake), чтобы 64 UDP-пакета не блокировали входящие TCP/QUIC соединения пиров.
    - В `session_by_cid()` для ещё не установленных сессий учитывать адрес пира `addr` при коллизии DCID.
    - В `tls_reload_cert()` проверять соответствие нового сертификата и ключа во временном контексте перед модификацией живого `tls_server_ctx`, обновлять `myself->tls_fingerprint` при перезагрузке и исправить off-by-one (`secs < 0`) при проверке истечения срока сертификата.

- [x] **1.9. Исправление онбординга (`invitation.c`), `store_invitee()`, `yamlconf.c` / `conf.c`, `autoif.c` и `acme.c`**
  - **Файлы:** `core/tincd/src/invitation.c`, `core/tincd/src/protocol_auth.c`, `core/tincd/src/conf.c`, `core/tincd/src/tincctl.c`, `core/tincd/src/net_setup.c`, `core/tincd/src/autoif.c`, `core/tincd/src/certcmd.c`, `core/tincd/src/yamlconf.c`
  - **Детали:**
    - В `finalize_join()` (`invitation.c:1388, 1670`) использовать `xstrdup()` для `netname` и пересоздавать пути `pidfilename`/`unixsocketname` после получения финального `NetName`.
    - В `invitation_yaml_apply()` и `finalize_join()` записывать сетевые опции из `PROPAGATED_OPTIONS` (`Transports`, `IndirectData`, `ClampMSS`, `Compression` и т.д.) в серверные `options:`, а не в `hosts.<invitee>`, и не записывать чужой `TlsFingerprint` в `hosts.<invitee>`.
    - В `store_invitee()` (`protocol_auth.c:231-257`) сохранять `Subnet` в классическом режиме и сразу добавлять подсети в `c->node->subnet_tree`.
    - В `conf.c`: починить чтение директории `conf.d` (строки 480–511), помечать строки из `hosts.<myself>` при `read_host_config()` в YAML-режиме для корректной работы `lookup_option_not_host()`, и синхронизировать `c->host_digest` при внешних правках `tinc.yaml`.
    - В `yamlconf_get_option()` (`yamlconf.c:824`) пропускать булевы скаляры через `bool_to_tinc()`.
    - В `cmd_config()` (`tincctl.c:2324-2429`) освобождать `yamlconf_unlock()` и файловые дескрипторы на всех ветках ошибок.
    - В `setup_myself_reloadable()` и `transport_node_read_config()` сбрасывать переопределяемые флаги перед перечитыванием конфига.
    - В `autoif_own_address()` (`autoif.c:45-54`) проверять принадлежность `/32` подсети пулу `address_pool`.
    - В `certcmd.c` сохранять сгенерированный `acme_account_key` даже при ошибке DNS-propagation/challenge, чтобы не исчерпывать лимит регистраций Let's Encrypt.

---

## Фаза 2: Исправления клиентских платформ (Windows, Android, Linux/Docker)

- [x] **2.1. Windows: Починка автообновления и устранение уязвимости TOCTOU (`updates.py`, `management.py`, `main.py`, `cli.py`)**
  - **Файлы:** `platforms/windows/backend/updates.py`, `platforms/windows/backend/management.py`, `platforms/windows/main.py`, `platforms/windows/cli.py`
  - **Детали:**
    - Сохранять оригинальное имя zip-ассета (`tincstack-v<ver>-windows-x86_64.zip`) при скачивании и сверять его с `SHA256SUMS`, а также проверять SHA256 самого `SHA256SUMS` по `rel.notes` (если указан в релизе) и защититься от Zip Slip (`..`).
    - Добавить обработку `--self-install` в `main.py` (до создания GUI `QApplication`) и исправить подкоманду в `cli.py`.
    - Реализовать реальное ожидание завершения процесса в `run_elevated(..., wait=True)` через `ShellExecuteExW` (`SEE_MASK_NOCLOSEPROCESS`) + `WaitForSingleObject`.
    - Перед запуском замены бинарников останавливать `tincd` (`rt.stop_all()`), выключать маршруты `FullTunnel` и освобождать файловые блокировки; очищать временную директорию обновления.

- [x] **2.2. Windows: Исправление `fulltunnel.py`, `runtime.py`, `transports.py`, `transports_panel.py`, `yaml_config.py`, `tinc_control.py`**
  - **Файлы:** `platforms/windows/backend/fulltunnel.py`, `platforms/windows/backend/runtime.py`, `platforms/windows/backend/transports.py`, `platforms/windows/gui/transports_panel.py`, `platforms/windows/backend/yaml_config.py`, `platforms/windows/backend/tinc_control.py`
  - **Детали:**
    - В `FullTunnel.step()` удалять из таблицы маршрутизации и `self.pins` устаревшие `/32` маршруты, которых больше нет в `want`.
    - В `_ipv4()` распаковывать `ip.ipv4_mapped` (`::ffff:a.b.c.d`), учитывать все хосты с `Address` при пиннинге.
    - В `Win32.route_table()` отфильтровывать `MIB_IPROUTE_TYPE_INVALID` и учитывать `MIB_IPROUTE_TYPE_DIRECT` (on-link маршруты).
    - Синхронизировать порядок поиска адаптера в `runtime._apply_wintun_mtu()` с `routes.adapter_aliases()`.
    - Добавить `"sf"` в `VALID_CARRIERS` и недостающие опции в `TRANSPORT_OPTIONS` (`transports.py`) и `KNOWN_OPTIONS` (`main.py`), исправить диапазон `self.quic_port.setRange(0, 65535)` в `transports_panel.py`.
    - В `yaml_config.py` захватывать `tinc.yaml.lock` при записи (`save()`, `save_text()`).

- [x] **2.3. Android: Исправление порчи конфига в `ConfigEditorActivity.kt`, `TincYaml.kt`, `PeerConfig.kt` и блэкхола в `TincVpnService.kt`**
  - **Файлы:** `platforms/android/app/src/main/java/org/pacien/tincapp/activities/config/ConfigEditorActivity.kt`, `platforms/android/app/src/main/java/org/pacien/tincapp/data/TincYaml.kt`, `platforms/android/app/src/main/java/org/pacien/tincapp/data/PeerConfig.kt`, `platforms/android/app/src/main/java/org/pacien/tincapp/activities/peers/PeersActivity.kt`, `platforms/android/app/src/main/java/org/pacien/tincapp/service/TincVpnService.kt`
  - **Детали:**
    - Игнорировать строки внутри `-----BEGIN ... -----END` PEM-блоков при парсинге и сплайсинге `key = value` в `ConfigEditorActivity.kt`, `PeerConfig.kt` и `TincYaml.kt`.
    - В `ConfigEditorActivity.Adapter.onBindViewHolder` удалять предыдущий `TextWatcher` перед `setText()`, в `Row.value()` возвращать `pending ?: original`, сохранять удалённые строки в `removed` для записи при `save()`, а в `addKeyDialog` проверять дубликаты только внутри выбранной секции.
    - В `TincYaml.replaceHostBlock()` искать `hosts:` строго внутри целевой сети `networks.<net>`, а в `blockEnd()` учитывать элементы списков `- item` на том же уровне отступа (`indent == keyIndent`).
    - В `PeerConfig.kt` исправить валидацию IPv6, добавить `obfsPort` и `frontPort` (`0..65535`), а в `PeersActivity.kt` устранить бесконечную рекурсию `renderStatic() <-> render()` при пустом списке хостов и учитывать порты транспортов (`quicPort`, `httpsPort`, `obfsPort`).
    - В `TincVpnService.kt` закрывать предыдущий `fdServerSocket` перед пересозданием и снимать запомненные маршруты (`0.0.0.0/0`), если после фазы быстрого опроса ни один пир не вышел на связь.

- [x] **2.4. Linux / Docker: Исправление публикации портов, `PORT=0` / `FRONT_PORT=0` и обработки сигналов в `entrypoint.sh` / `join.sh`**
  - **Файлы:** `platforms/linux/docker/docker-compose.yml`, `platforms/linux/docker/compose.release.yml`, `platforms/linux/docker/join.sh`, `platforms/linux/docker/entrypoint.sh`
  - **Детали:**
    - Актуализировать описание единого порта для всех транспортов в `docker-compose.yml` и `compose.release.yml`.
    - В `join.sh` обрабатывать `PORT=0` наравне с пустым `PORT` (использовать `compose.leaf.yml` без публикации `0:0`) и безопасно перезаписывать `COMPOSE_FILE` в `.env`.
    - В `entrypoint.sh` запускать `sleep` в `renew_loop` в фоне с `wait`, чтобы контейнер мгновенно завершался по `SIGTERM`, и убирать квадратные скобки у IPv6 `PUBLIC_ADDRESS` без порта.

---

## Фаза 3: Сборка и тестирование
- [x] **3.1. Сборка C-ядра (`tincd`, `tinc`) и прогон существующих и новых юнит/интеграционных тестов** (20/20 OK, 2 EXPECTEDFAIL, 0 Fail)
- [x] **3.2. Прогон Python-тестов (`platforms/windows/tests/`) и проверка Kotlin/Android и Docker-скриптов** (124 passed, 0 failed)

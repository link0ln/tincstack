# Tinc Mesh VPN: Android client and user interface
# Copyright (C) 2017-2023 Euxane P. TRAN-GIRARD
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

-keep class org.apache.commons.** { *; }
-keep class ch.qos.** { *; }
-keep class org.slf4j.** { *; }
-keepattributes *Annotation*
-dontobfuscate
-dontwarn org.apache.commons.**
-dontwarn ch.qos.logback.core.net.*
-dontwarn sun.misc.Unsafe
-dontwarn build.IgnoreJava8API

# SnakeYAML reads and writes tinc.yaml. Its introspector references java.beans,
# which does not exist on Android; nothing the app calls reaches that path, so
# the references are only warnings -- but R8 fails the release build on them.
# The classes themselves are kept whole because SnakeYAML resolves node types
# reflectively, exactly like the other libraries kept above.
# (Without this, `assembleRelease` dies in minifyReleaseWithR8 with
# "Missing class java.beans.BeanInfo ... and 4 others".)
-dontwarn java.beans.**
-keep class org.yaml.snakeyaml.** { *; }

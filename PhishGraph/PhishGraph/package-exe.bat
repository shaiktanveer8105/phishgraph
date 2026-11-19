@echo off
REM Optional: build a Windows .exe app image (needs JDK 17+ jpackage and WiX only for installers)
call build.bat
jar --create --file phishgraph.jar --main-class phishgraph.Main -C out .
jpackage --type app-image --name PhishGraph --input . --main-jar phishgraph.jar --dest dist

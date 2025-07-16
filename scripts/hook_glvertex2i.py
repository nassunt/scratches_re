import frida
import sys
import os
from datetime import datetime

# Write messages to file
with open("frida_hook_dump.txt", "w") as f:

    # Handle messages from Frida
    def on_message(message, data):
        f.write("[" + str(datetime.now()) +"]" + str(message) + "\n")


    exe_path = "C:/Program Files (x86)/Got Game/Scratches Director's Cut/scream.exe"
    work_dir = os.path.dirname(exe_path)

    # Start exe and grab PID
    pid = frida.spawn([exe_path], cwd=work_dir)

    # Attach to process
    session = frida.attach(pid)

    # Frida script
    script = session.create_script("""                       
    // Print all calls to glVertex2i
    Interceptor.attach(Module.getGlobalExportByName("glVertex2i"), {
        onEnter(args) {
                                   
            var x = args[0].toInt32();
            var y = args[1].toInt32();
                                   
            if(x == 0 && y == 704){
                args[1] = ptr(1080);
            }
            else if(x == 1312 && y == 704){
                args[0] = ptr(1920);
                args[1] = ptr(1080);
            }
            else if(x == 1312 && y == -685){
                args[0] = ptr(1920);
                args[1] = ptr(-1080);
            }
            else if(x == 0 && y == -685){
                args[1] = ptr(-1080);
            }

            send("glVertex2i called with x: " + args[0].toInt32() + ", y: " + args[1].toInt32());
        }
    });
                                
    """)

    script.on('message', on_message)
    script.load()

    # Start the process
    frida.resume(pid)

    sys.stdin.read()
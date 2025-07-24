import frida
import sys
import os
from datetime import datetime
import ctypes

# Write messages to file
with open("frida_hook_dump.txt", "w") as f:

    # Get screen size
    user32 = ctypes.windll.user32
    screen_width = user32.GetSystemMetrics(0)
    screen_height = user32.GetSystemMetrics(1)

    print(str(screen_width) + "x" + str(screen_height))

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

    // Get variables from python
    function listen(){
        recv(function(message){
            var screen_width = message.payload.screen_width;
            var screen_height = message.payload.screen_height;
                                   
            globalThis.screenSettings = { screen_width, screen_height };
        })
    }                           
    listen();
                                   
    // Print all calls to glVertex2i
    Interceptor.attach(Module.getGlobalExportByName("glVertex2i"), {
        onEnter(args) {
                                   
            var x = args[0].toInt32();
            var y = args[1].toInt32();
                                   
            var black_bar_height_top = 424;
            var black_bar_height_bottom = 391;
                                   
            var width_modification = 102;
                                   
            if(x == 0 && y == 704){             // (0,0)
                args[1] = ptr(globalThis.screenSettings.screen_height - black_bar_height_top);
            }
            else if(x == 1312 && y == 704){     // (1,0)
                args[0] = ptr(globalThis.screenSettings.screen_width - width_modification);
                args[1] = ptr(globalThis.screenSettings.screen_height - black_bar_height_top);
            }
            else if(x == 1312 && y == -685){    // (1,1)
                args[0] = ptr(globalThis.screenSettings.screen_width - width_modification);
                args[1] = ptr(-globalThis.screenSettings.screen_height + black_bar_height_bottom);
            }
            else if(x == 0 && y == -685){       // (0,1)
                args[1] = ptr(-globalThis.screenSettings.screen_height + black_bar_height_bottom);
            }
            else if(x == 0 && y == -662){
                args[1] = ptr(-1080);
            }
            else if(x == 1312 && y == -662){
                args[0] = ptr(1920);
                args[1] = ptr(-1080);
            }
            

            send("glVertex2i called with x: " + args[0].toInt32() + ", y: " + args[1].toInt32());
        }
    });
                                
    """)

    script.on('message', on_message)
    script.load()

    # Send variables to Frida script
    script.post({
        "type": "data",
        "payload": {
          "screen_width": screen_width,
          "screen_height": screen_height
        }
    })


    # Start the process
    frida.resume(pid)

    sys.stdin.read()
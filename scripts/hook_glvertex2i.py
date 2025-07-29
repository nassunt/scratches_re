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

    const VK_ESCAPE = 0x1B;
    const WM_KEYDOWN = 0x100;
    const WM_LBUTTONDOWN = 0x201;

    // Log esc keystrokes to find additional textures that are being drawn incorrectly
    // Also get cursor location for mouse clicks
    Interceptor.attach(Module.getGlobalExportByName("PeekMessageA"),{
        onEnter(args){
            this.msgPtr = args[0];
        },
        onLeave(retval){
            try{
                if (retval.toInt32() === 0) return;
                if (!this.msgPtr || this.msgPtr.isNull()) return;

                // Read memory addresses for the message and wParam values
                const message = this.msgPtr.add(4).readU32();
                const wParam  = this.msgPtr.add(8).readU32();
                const lParam = this.msgPtr.add(12).readU32();

                // Case if esc key is pressed
                if (message === WM_KEYDOWN && wParam === VK_ESCAPE){
                    send("Esc pressed!");
                }
                // Case for mouse click
                if (message === WM_LBUTTONDOWN){
                    
                    const x = lParam & 0xffff;
                    const y = (lParam >> 16) & 0xffff;
                    
                    // TODO convert to unsigned int

                    send("Mouse click at x: " + x + ", y: " + y);
                }
            
            }catch (e){
                console.log("Read error in PeekMessage hook:", e);
            }
        }
    });

    /*                     
    Interceptor.attach(Module.getGlobalExportByName("glTexCoord2f"),{
        onEnter(args){
            var s = args[0].toInt32();
            var t = args[1].toInt32();
            
            if (s == 0 && t == 1031798784){ // 0 and 0.6
                args[1] = ptr(0);
            }
            else if(s == 1065353216 && t == 1031798784){
                args[1] = ptr(0);
            }
            else if(s == 1065353216 && t == 1064304640){
                args[1] = ptr(1065353216);
            }
            else if(s == 0 && t == 1064304640){
                args[1] = ptr(1065353216);
            }
        }
    });
    */

    // Print all calls to glVertex2i
    Interceptor.attach(Module.getGlobalExportByName("glVertex2i"),{
        onEnter(args){
                                   
            var x = args[0].toInt32();
            var y = args[1].toInt32();
                                   
            var black_bar_height_top = 424;
            var black_bar_height_bottom = 391;
                                   
            var width_modification = 102;
                                   
            var new_width =  globalThis.screenSettings.screen_width - width_modification;
            var new_height_top = globalThis.screenSettings.screen_height - black_bar_height_top;
            var new_height_bottom = -globalThis.screenSettings.screen_height + black_bar_height_bottom;
                                   
                              
            if(x == 0 && y == 704){          // (0,0)  Fix for most textures and videos 
                args[1] = ptr(new_height_top);
            }
            else if(x == 1312 && y == 704){  // (1,0)
                args[0] = ptr(new_width);
                args[1] = ptr(new_height_top);
            }
            else if(x == 1312 && y == -685){ // (1,1)
                args[0] = ptr(new_width);
                args[1] = ptr(new_height_bottom);
            }
            else if(x == 0 && y == -685){    // (0,1)
                args[1] = ptr(new_height_bottom);
            }
            else if(x == 0 && y == -662){    // (0,1) Fix for clipped corner in videos
                args[1] = ptr(new_height_bottom);
            }
            else if(x == 1312 && y == -662){ // (1,1)
                args[0] = ptr(new_width);
                args[1] = ptr(new_height_bottom);
            }
            else if(x == 0 && y == 1016){    // (0,0) Fix for black background 
                args[1] = ptr(new_height_top);
            }
            else if(x == 1024 && y == 704){  // (1,0)
                args[0] = ptr(new_width);
                args[1] = ptr(new_height_top);
            }
            else if(x == 1024 && y == -320){ // (1,1)
                args[0] = ptr(new_width);
                args[1] = ptr(new_height_bottom);
            }
            else if(x == 0 && y == -320){    // (0,1)
                args[1] = ptr(new_height_bottom);
            }
            else if(x == 1024 && y == 64){   // (1, 0.6) Fix transition (first call is (0, 0.6) but doesn't need to be changed) (this one has different glTexCoord values basically meaning it is zoomed in)
                args[0] = ptr(new_width - 537);
            }
            else if(x == 1024 && y == 960){  // (1, 0.975)
                args[0] = ptr(new_width - 537);
                args[1] = ptr(new_height_top);
            }
            else if(x == 0 && y == 960){    // (0, 0.975)
                args[1] = ptr(new_height_top);
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
import frida
import sys
import os
from datetime import datetime

# Write messages to file
with open("frida_gl_dump.txt", "w") as f:

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

    const VK_ESCAPE = 0x1B;
    const WM_KEYDOWN = 0x100;

    // Log esc keystrokes to find additional textures that are being drawn incorrectly
    Interceptor.attach(Module.getGlobalExportByName("PeekMessageA"), {
        onEnter(args) {
            this.msgPtr = args[0];
        },
        onLeave(retval) {
            try {
                if (retval.toInt32() === 0) return;
                if (!this.msgPtr || this.msgPtr.isNull()) return;

                // Read memory addresses for the message and wParam values
                const message = this.msgPtr.add(4).readU32();
                const wParam  = this.msgPtr.add(8).readU32();

                if (message === WM_KEYDOWN && wParam === VK_ESCAPE) {
                    send("Esc pressed!");
                }
            } catch (e) {
                console.log("Read error in PeekMessage hook:", e);
            }
        }
    });

    // Print all calls to glBegin
    Interceptor.attach(Module.getGlobalExportByName("glBegin"), {
        onEnter(args) {
            send("glBegin called with mode: " + args[0].toInt32());
        }
    });

    // Print all calls to glViewport
    Interceptor.attach(Module.getGlobalExportByName("glViewport"), {
        onEnter(args) {
            send("glViewport called with x: " + args[0].toInt32() + ", y: " + args[1].toInt32() + ", width: " + args[2].toInt32() + ", height: " + args[3].toInt32());
        }
    });

    // Print all calls to glBindTexture
    Interceptor.attach(Module.getGlobalExportByName("glBindTexture"), {
        onEnter(args) {
            send("glBindTexture called with target: " + args[0].toInt32() + ", texture: " + args[1].toInt32());
        }
    });
                                
    // Print all calls to glVertex2i
    Interceptor.attach(Module.getGlobalExportByName("glVertex2i"), {
        onEnter(args) {
            send("glVertex2i called with x: " + args[0].toInt32() + ", y: " + args[1].toInt32());
        }
    });
                                   
    // Print all calls to glVertex3f
    Interceptor.attach(Module.getGlobalExportByName("glVertex3f"), {
        onEnter(args) {
            send("glVertex3f called with x: " + args[0].toInt32() + ", y: " + args[1].toInt32() + ", z: " + args[2].toInt32());
        }
    });
                                   
    // Print all calls to glVertex3i
    Interceptor.attach(Module.getGlobalExportByName("glVertex3i"), {
        onEnter(args) {
            send("glVertex3i called with x: " + args[0].toInt32() + ", y: " + args[1].toInt32() + ", z: " + args[2].toInt32());
        }
    });

    // Print all calls to glOrtho
    Interceptor.attach(Module.getGlobalExportByName("glOrtho"), {
        onEnter(args) {
            send("glOrtho called with left: " + args[0].toInt32() + ", right: " + args[1].toInt32() + ", bottom: " + args[2].toInt32() + ", top: " + args[3].toInt32() + ", nearVal: " + args[4].toInt32() + ", farVal: " + args[5].toInt32());
        }
    });
                                   
    // Print all calls to glMatrixMode
    Interceptor.attach(Module.getGlobalExportByName("glMatrixMode"), {
        onEnter(args) {
            send("glMatrixMode called with mode: " + args[0].toInt32());
        }
    });
                                   
    // Print all calls to glLoadIdentity
    Interceptor.attach(Module.getGlobalExportByName("glLoadIdentity"), {
        onEnter(args) {
            send("glLoadIdentity called");
        }
    });
                                   
    // Print all calls to glTexCoord2f
    Interceptor.attach(Module.getGlobalExportByName("glTexCoord2f"), {
        onEnter(args) {
            send("glTexCoord2f called with s: " + args[0].toInt32() + ", t: " + args[1].toInt32());
        }
    });
                                   
    // Print all calls to glTexImage2D
    Interceptor.attach(Module.getGlobalExportByName("glTexImage2D"), {
        onEnter(args) {
            send("glTexImage2D called with target: " + args[0].toInt32() + ", level: " + args[1].toInt32() + ", internalformat: " + args[2].toInt32() + ", width: " + args[3].toInt32() + ", height: " + args[4].toInt32() + ", border: " + args[5].toInt32() + ", format: " + args[6].toInt32() + ", type: " + args[7].toInt32() + ", data: " + args[8].toInt32());
        }
    });
                                   
    // Print all calls to glTexSubImage2D
    Interceptor.attach(Module.getGlobalExportByName("glTexSubImage2D"), {
        onEnter(args) {
            send("glTexSubImage2D called with target: " + args[0].toInt32() + ", level: " + args[1].toInt32() + ", xoffset: " + args[2].toInt32() + ", yoffest: " + args[3].toInt32() + ", width: " + args[4].toInt32() + ", height: " + args[5].toInt32() + ", format: " + args[6].toInt32() + ", type: " + args[7].toInt32() + ", pixels: " + args[8].toInt32());
        }
    });
                                   
    // Print all calls to glEnd
    Interceptor.attach(Module.getGlobalExportByName("glEnd"), {
        onEnter(args) {
            send("glEnd called");
        }
    });
                                
    """)

    script.on('message', on_message)
    script.load()

    # Start the process
    frida.resume(pid)

    sys.stdin.read()
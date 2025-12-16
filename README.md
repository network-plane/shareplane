# shs - Simple HTTP Server

A lightweight HTTP server written in Go for serving files and directories over HTTP. Perfect for quick file sharing.

## Features

- **Simple & Fast**: Minimal overhead, easy to use
- **File & Directory Serving**: Serve individual files or entire directories
- **HTTP Range Support**: Supports HTTP Range requests (206 Partial Content) for resuming downloads and partial file fetches
- **Download Statistics**: Track downloads with byte counts and request statistics
- **Customizable Binding**: Configure IP address and port
- **Network Interface Detection**: When binding to `0.0.0.0`, automatically shows all available IP addresses
- **File Listing**: Automatic HTML file listing at the root path
- **Glob Pattern Support**: Use glob patterns to select multiple files
- **Hidden File Filtering**: Hidden files (starting with `.`) are excluded from listings by default
- **File Hashing**: Optional SHA1 hash calculation and display for files in listings
- **Real-time Progress**: See download progress as files are served
- **Graceful Shutdown**: Print statistics on exit (SIGINT/SIGTERM)

## Installation

### Build from Source

```bash
go build -o shs
```

## Usage

### Basic Usage

Serve a single file:
```bash
./shs file.txt
```

Serve multiple files:
```bash
./shs file1.txt file2.txt file3.txt
```

Serve a directory:
```bash
./shs /path/to/directory
```

Serve multiple files and directories:
```bash
./shs file.txt /path/to/dir1 /path/to/dir2
```

### Command-Line Options

- `--port`: Port to listen on (default: `8080`)
  ```bash
  ./shs --port 3000 file.txt
  ```

- `--ip`: IP address to bind to (default: `0.0.0.0` - all interfaces)
  ```bash
  ./shs --ip 127.0.0.1 file.txt
  ```
  When binding to `0.0.0.0`, the server will display all available network interfaces and their IP addresses.

- `--show-hidden`: Show files and directories starting with a dot (`.`) in file listings (hidden files are hidden by default)
  ```bash
  ./shs --show-hidden /path/to/directory
  ```

- `--hash`: Calculate and display SHA1 hash for files in the listing
  ```bash
  ./shs --hash /path/to/directory
  ```

- `--max-hash-size`: Maximum file size (in bytes) to calculate hash for (0 = no limit, default: 0)
  ```bash
  ./shs --hash --max-hash-size 10485760 /path/to/directory  # Only hash files up to 10MB
  ```

- Environment Variables:
  - `PORT`: Set the port (same as `--port`)
  - `IP`: Set the IP address (same as `--ip`)

### Examples

Serve files on a custom port:
```bash
./shs --port 9000 document.pdf image.jpg
```

Serve only on localhost:
```bash
./shs --ip 127.0.0.1 --port 8080 /path/to/files
```

Use glob patterns:
```bash
./shs *.txt *.pdf
```

Show hidden files in listings (hidden files are hidden by default):
```bash
./shs --show-hidden /path/to/directory
```

Show SHA1 hashes for files:
```bash
./shs --hash /path/to/directory
```

Show SHA1 hashes with size limit (only hash files up to 100MB):
```bash
./shs --hash --max-hash-size 104857600 /path/to/directory
```

Access files:
- Visit `http://localhost:8080/` to see a file listing
- Access files directly: `http://localhost:8080/filename.txt`

When binding to `0.0.0.0`, the server will show output like:
```bash
Serving on http://0.0.0.0:8080
Available on:
  http://192.168.1.100:8080
  http://10.0.0.5:8080
  http://127.0.0.1:8080
  http://localhost:8080
```

## HTTP Range Requests

The server fully supports HTTP Range requests (RFC 7233), which enables:
- **Resuming Downloads**: Clients can resume interrupted downloads by requesting specific byte ranges
- **Partial Fetches**: Clients can request specific portions of files (e.g., for video streaming or large file processing)
- **Efficient Transfers**: Reduces bandwidth usage when only part of a file is needed

The server automatically handles `Range` headers and responds with `206 Partial Content` when appropriate. This is transparent to users - any HTTP client that supports Range requests will automatically benefit from this feature.

## Statistics

The server tracks download statistics for each file:
- Number of times each file was downloaded
- Total bytes sent for each file
- Total bytes sent for file listings

Statistics are printed when the server is terminated (Ctrl+C or SIGTERM).

## License

See [LICENSE](LICENSE) file for details.

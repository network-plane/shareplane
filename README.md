# shareplane - Simple HTTP Server

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
- **Customizable Colors**: Customize the color scheme of the file listing interface
- **Bandwidth Limiting**: Optional bandwidth throttling for file transfers
- **Rate Limiting**: Built-in DoS protection with per-IP request rate limiting (default: 20 req/s)
- **Idle Timeout**: Automatically shut down the server after a period of inactivity
- **Real-time Progress**: See download progress as files are served
- **Graceful Shutdown**: Print statistics on exit (SIGINT/SIGTERM)

## Installation

### Build from Source

```bash
go build -o shareplane
```

## Usage

### Basic Usage

Serve a single file:
```bash
./shareplane file.txt
```

Serve multiple files:
```bash
./shareplane file1.txt file2.txt file3.txt
```

Serve a directory:
```bash
./shareplane /path/to/directory
```

Serve multiple files and directories:
```bash
./shareplane file.txt /path/to/dir1 /path/to/dir2
```

### Command-Line Options

- `--port`: Port to listen on (default: `8080`)
  ```bash
  ./shareplane --port 3000 file.txt
  ```

- `--ip`: IP address to bind to (default: `0.0.0.0` - all interfaces)
  ```bash
  ./shareplane --ip 127.0.0.1 file.txt
  ```
  When binding to `0.0.0.0`, the server will display all available network interfaces and their IP addresses.

- `--show-hidden`: Show files and directories starting with a dot (`.`) in file listings (hidden files are hidden by default)
  ```bash
  ./shareplane --show-hidden /path/to/directory
  ```

- `--hash`: Calculate and display SHA1 hash for files in the listing
  ```bash
  ./shareplane --hash /path/to/directory
  ```

- `--max-hash-size`: Maximum file size (in bytes) to calculate hash for (0 = no limit, default: 0)
  ```bash
  ./shareplane --hash --max-hash-size 10485760 /path/to/directory  # Only hash files up to 10MB
  ```

- `--bw-limit`: Bandwidth limit for file transfers (e.g., `5MB`, `250KB`, `5M`, `1.4G`, or plain bytes). No limit if not specified.
  ```bash
  ./shareplane --bw-limit 5MB /path/to/directory  # Limit to 5MB/s
  ./shareplane --bw-limit 1.4G /path/to/directory  # Limit to 1.4GB/s
  ```

- `--rate-limit`: Rate limit: maximum requests per second per IP address (default: 20, use 0 to disable). Helps protect against DoS attacks while allowing normal browsing.
  ```bash
  ./shareplane --rate-limit 30 /path/to/directory    # Allow 30 requests/second per IP
  ./shareplane --rate-limit 0 /path/to/directory      # Disable rate limiting
  ./shareplane /path/to/directory                     # Uses default: 20 requests/second per IP
  ```

- `--reload`: Enable auto-reload: monitor files for changes in real-time using file system notifications (new files, removed files, modified files)
  ```bash
  ./shareplane --reload /path/to/directory
  ```

- `--idle`: Idle timeout: server shuts down after this period of inactivity. Default: 15m if flag is set without value. Supports units: M (minutes), H (hours), D (days), W (weeks), Mo (months). Examples: `15m`, `1H`, `4D`, `1W`, `1Mo`
  ```bash
  ./shareplane --idle file.txt                    # Default: 15 minutes
  ./shareplane --idle 30m /path/to/directory     # 30 minutes
  ./shareplane --idle 2H /path/to/directory      # 2 hours
  ./shareplane --idle 1D /path/to/directory       # 1 day
  ./shareplane --idle 1W /path/to/directory       # 1 week
  ```

- `--colours`: Customize the color scheme of the file listing interface. Requires 7 comma-separated colors in this order:
  1. Background (body background)
  2. Text (heading text)
  3. Table header Background
  4. Table header text
  5. Table Background
  6. Table filename text (link color)
  7. Table other text
  ```bash
  ./shareplane --colours "#000000,#FFFFFF,#FF0000,#FFFFFF,#CCCCCC,#0000FF,#333333" /path/to/directory
  ```
  Colors can be specified as hex codes (with or without `#`) or named CSS colors (e.g., `red`, `blue`, `white`).

- Environment Variables:
  - `PORT`: Set the port (same as `--port`)
  - `IP`: Set the IP address (same as `--ip`)

### Examples

Serve files on a custom port:
```bash
./shareplane --port 9000 document.pdf image.jpg
```

Serve only on localhost:
```bash
./shareplane --ip 127.0.0.1 --port 8080 /path/to/files
```

Use glob patterns:
```bash
./shareplane *.txt *.pdf
```

Show hidden files in listings (hidden files are hidden by default):
```bash
./shareplane --show-hidden /path/to/directory
```

Show SHA1 hashes for files:
```bash
./shareplane --hash /path/to/directory
```

Show SHA1 hashes with size limit (only hash files up to 100MB):
```bash
./shareplane --hash --max-hash-size 104857600 /path/to/directory
```

Limit bandwidth to 5MB/s:
```bash
./shareplane --bw-limit 5MB /path/to/directory
```

Customize colors with a dark theme:
```bash
./shareplane --colours "#1a1a1a,#e0e0e0,#2d2d2d,#ffffff,#252525,#4a9eff,#cccccc" /path/to/directory
```

Customize colors with a light blue theme:
```bash
./shareplane --colours "#f0f8ff,#1a1a1a,#4a90e2,#ffffff,#ffffff,#0066cc,#333333" /path/to/directory
```

Customize colors using named colors:
```bash
./shareplane --colours "black,white,red,white,gray,blue,darkgray" /path/to/directory
```

Access files:
- Visit `http://localhost:8080/` to see a file listing
- Access files directly: `http://localhost:8080/filename.txt`

## API Endpoint

The server provides a JSON API endpoint for programmatic access to file listings. This is useful for scripts, tools, and automation.

### `/api/files`

Returns a JSON response with file listings, totals, and metadata.

**Query Parameters:**
- `path` (optional): Directory path to list. If not provided, lists all shared files/directories.

**Response Format:**
```json
{
  "files": [
    {
      "name": "/full/path/to/file.txt",
      "displayName": "file.txt",
      "size": 1024,
      "modTime": "2024-01-01T12:00:00Z",
      "hash": "abc123...",
      "isDir": false
    }
  ],
  "totalSize": 1048576,
  "fileCount": 10,
  "showHash": true
}
```

**Response Fields:**
- `files`: Array of file/directory objects
  - `name`: Full absolute path (internal use)
  - `displayName`: Relative path for display
  - `size`: File size in bytes
  - `modTime`: Modification time (ISO 8601 format)
  - `hash`: SHA1 hash (empty if not calculated or disabled)
  - `isDir`: Boolean indicating if this is a directory
- `totalSize`: Total size of all files in bytes (directories excluded)
- `fileCount`: Total number of files (directories excluded)
- `showHash`: Boolean indicating if hash calculation is enabled

### API Usage Examples

**List all shared files (root):**
```bash
curl http://localhost:8080/api/files
```

**List files in a specific directory:**
```bash
curl "http://localhost:8080/api/files?path=subdirectory"
```

**Pretty-print JSON response:**
```bash
curl http://localhost:8080/api/files | jq
```

**List files and extract only file names:**
```bash
curl -s http://localhost:8080/api/files | jq -r '.files[] | select(.isDir == false) | .displayName'
```

**Get total size of all files:**
```bash
curl -s http://localhost:8080/api/files | jq '.totalSize'
```

**List files with their sizes (formatted):**
```bash
curl -s http://localhost:8080/api/files | jq -r '.files[] | "\(.displayName): \(.size) bytes"'
```

**Download a file using curl:**
```bash
curl -O http://localhost:8080/filename.txt
```

**Download with progress bar:**
```bash
curl -# -O http://localhost:8080/largefile.zip
```

**Resume a partial download:**
```bash
curl -C - -O http://localhost:8080/largefile.zip
```

**Check if a file exists (HEAD request):**
```bash
curl -I http://localhost:8080/filename.txt
```

**Get file metadata without downloading:**
```bash
curl -I http://localhost:8080/filename.txt
```

**List files in a nested directory:**
```bash
curl "http://localhost:8080/api/files?path=docs/subdir"
```

**Filter directories only:**
```bash
curl -s http://localhost:8080/api/files | jq '.files[] | select(.isDir == true) | .displayName'
```

**Get files with hashes (when --hash is enabled):**
```bash
curl -s http://localhost:8080/api/files | jq '.files[] | select(.hash != "") | {name: .displayName, hash: .hash}'
```

**Save API response to file:**
```bash
curl -s http://localhost:8080/api/files -o file_listing.json
```

**Use API in a script (bash example):**
```bash
#!/bin/bash
API_URL="http://localhost:8080/api/files"
FILES=$(curl -s "$API_URL" | jq -r '.files[] | select(.isDir == false) | .displayName')

for file in $FILES; do
    echo "Processing: $file"
    # Your processing logic here
done
```

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

## Proxy Support

When running behind a reverse proxy (such as frps, nginx, or Cloudflare), the server automatically detects and uses the real client IP address from proxy headers. The server checks the following headers in order:

1. `X-Forwarded-For` - Most common header, contains the original client IP
2. `X-Real-IP` - Common in nginx and other proxies
3. `X-Forwarded` - Alternative format for forwarded IPs
4. `CF-Connecting-IP` - Cloudflare-specific header

If no proxy headers are present, the server falls back to the connection's `RemoteAddr`. The real client IP is displayed in the download logs, making it easy to track which clients are downloading files even when behind a proxy.

## Statistics

The server tracks download statistics for each file:
- Number of times each file was downloaded
- Total bytes sent for each file
- Total bytes sent for file listings

Statistics are printed when the server is terminated (Ctrl+C or SIGTERM).

## License

See [LICENSE](LICENSE) file for details.

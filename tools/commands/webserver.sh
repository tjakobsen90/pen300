#!/bin/bash

declare -a server_pids

payload_base_path="/home/tijmen/pen300/genpayload/output"
portexec_base_path="/home/tijmen/pen300/smbshare/source"

source_files_payloads=(
    "$portexec_base_path/dll-revshell/bin/x64/Release/dll-revshell.dll"
    "$portexec_base_path/exec-revshell/bin/x64/Release/exec-revshell.exe"
    "$payload_base_path/li-rshell.elf"
    "$payload_base_path/li-rshell.so"
)

for file in "$payload_base_path"/evil_*.so; do
    source_files_payloads+=("$file")
done

source_files_portexecs=(
    "$portexec_base_path/uninstall-bypass/bin/x64/Release/uninstall-bypass.exe"
    "$portexec_base_path/uninstall-manual/bin/x64/Release/uninstall-manual.exe"
    "$portexec_base_path/latexec/bin/x64/Release/latexec.exe"
    "$portexec_base_path/rdpthief/bin/x64/Release/rdpthief.exe"
    "$portexec_base_path/sqlexec/bin/x64/Release/sqlexec.exe"
)

source_files=("${source_files_payloads[@]}" "${source_files_portexecs[@]}")
web_dir="/home/tijmen/pen300/www"
destination_dir_payloads="$web_dir/pl/"
destination_dir_portexecs="$web_dir/pe/"

main() {
    for file in "${source_files_payloads[@]}"; do
        copy_file "$file" "$destination_dir_payloads"
    done

    for file in "${source_files_portexecs[@]}"; do
        copy_file "$file" "$destination_dir_portexecs"
    done

    webserver
    monitoring
}

copy_file() {
    local file="$1"
    local destination_dir="$2"
    if cp "$file" "$destination_dir" 2>/dev/null; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Copied: $(basename "$file") to $destination_dir"
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Error: $(basename "$file")" >&2
    fi
}

monitoring() {
    while true; do
        changed_file=$(inotifywait -q -e modify "${source_files_payloads[@]}" "${source_files_portexecs[@]}" | awk '{print $1}')
        if [ -n "$changed_file" ]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') - Change detected in $(basename "$changed_file")"
            sleep 5
            if [[ " ${source_files_payloads[@]} " =~ " ${changed_file} " ]]; then
                copy_file "$changed_file" "$destination_dir_payloads"
            elif [[ " ${source_files_portexecs[@]} " =~ " ${changed_file} " ]]; then
                copy_file "$changed_file" "$destination_dir_portexecs"
            fi
        fi
    done
}

webserver() {
    sudo python3 -m http.server 80 -d "$web_dir" &
    server_pid_80=$!

    sudo python3 -m http.server 81 -d "$web_dir" &
    server_pid_81=$!

    sudo python3 -m http.server 8081 -d "$web_dir" &
    server_pid_8081=$!

    server_pids=($server_pid_80 $server_pid_81 $server_pid_8081)
}

stop_server() {
    echo "Stopping the server..."
    for pid in "${server_pids[@]}"; do
        sudo kill "$pid"
    done
    exit 0
}

trap stop_server SIGINT SIGTERM EXIT

main

# Step 1: Use a minimal base image for running the binary
FROM alpine:latest

# Step 2: Copy the compiled Go binary into the container
COPY ebpf_loader /usr/local/bin/ebpf_loader

# Step 3: Make sure the binary is executable
RUN chmod +x /usr/local/bin/ebpf_loader

# Step 4: Set the entry point to Go binary
ENTRYPOINT ["/usr/local/bin/ebpf_loader"]

# Optionally, specify the default command
CMD []

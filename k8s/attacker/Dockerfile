# Start with an official Ubuntu base image
FROM ubuntu:latest

# Update and install necessary packages
RUN apt-get update && \
    apt-get install -y \
    curl \
    unzip  


# AWS CLI installation
RUN	curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
RUN	unzip awscliv2.zip && ./aws/install

# Clean up to reduce the image size
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

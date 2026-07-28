Guide for multi-platform image in registry handling

# Upload flow
On a single x64 machine I need to build both images x64 and arm64 and upload them to the registry as a single image.

```
# Installs dependencies for building multi-platform images
docker run --privileged --rm tonistiigi/binfmt --install all

# Creates a new builder instance
docker buildx create --name owlsm-multi --driver docker-container --bootstrap --use

# Logs in to the registry
echo "$GITHUB_TOKEN" | docker login ghcr.io -u "$YOUR_GITHUB_USER" --password-stdin

# build and push the image
cd /tmp
git clone https://github.com/Cybereason-Public/owLSM.git
cd owLSM
docker buildx build --platform linux/amd64,linux/arm64 -t ghcr.io/cybereason-public/owlsm-ci:latest --push .

# verify the image
docker buildx imagetools inspect ghcr.io/cybereason-public/owlsm-ci:latest
```

# Users - How to use the image
Our image is a multi-platform image, which means you can create a x64/arm64 container from it on a x64/arm64 machine.
For building an x64 release you need to pull an x64 image.
For building an arm64 release you need to pull an arm64 image.

## Machine and container are the same arch
Most of the time you will need a container that is the same arch as the machine.
In those situations, docker will automatically pull and build the correct image architecture.
Just do:
```
# Pull the Docker image
docker pull ghcr.io/cybereason-public/owlsm-ci:latest

# Start the container
docker run -it --rm -v "$PWD":/workspace -w /workspace ghcr.io/cybereason-public/owlsm-ci:latest bash
```

## Machine and container are different arch
If you need a container that is a different arch than the machine, you need to specify the architecture when pulling the image.
For example, if you are running a x64 machine and you need to build an aarch64 image, you need to pull the aarch64 image.
``` 
# Installs dependencies for building multi-platform images
docker run --privileged --rm tonistiigi/binfmt --install all

# pull specifically the arm64 image
docker pull --platform linux/arm64 ghcr.io/cybereason-public/owlsm-ci:latest

# Start the container
docker run -it --rm --platform linux/arm64 -v "$PWD":/workspace -w /workspace ghcr.io/cybereason-public/owlsm-ci:latest bash
```
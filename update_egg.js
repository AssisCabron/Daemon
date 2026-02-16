// Native fetch is available in Node 24

const eggId = '40347556-d91b-4df5-a7c7-bdca79709a4c';
const payload = {
    installation_script: `#!/bin/ash
# Paper Installation Script
#
# Server Files: /mnt/server
PROJECT=paper

# Simplified script to avoid JS escaping hell, assuming generic flow
cd /mnt/server

# Default valus
MINECRAFT_VERSION=\${MINECRAFT_VERSION:-latest}
BUILD_NUMBER=\${BUILD_NUMBER:-latest}

echo "Using version \${MINECRAFT_VERSION}"

# Get Latest Version if needed
if [ "\${MINECRAFT_VERSION}" == "latest" ]; then
    MINECRAFT_VERSION=$(curl -s https://api.papermc.io/v2/projects/\${PROJECT} | jq -r '.versions[-1]')
fi

# Get Latest Build if needed
if [ "\${BUILD_NUMBER}" == "latest" ]; then
    BUILD_NUMBER=$(curl -s https://api.papermc.io/v2/projects/\${PROJECT}/versions/\${MINECRAFT_VERSION} | jq -r '.builds[-1]')
fi

JAR_NAME=\${PROJECT}-\${MINECRAFT_VERSION}-\${BUILD_NUMBER}.jar
DOWNLOAD_URL=https://api.papermc.io/v2/projects/\${PROJECT}/versions/\${MINECRAFT_VERSION}/builds/\${BUILD_NUMBER}/downloads/\${JAR_NAME}

echo "Downloading \${JAR_NAME} from \${DOWNLOAD_URL}"

curl -o \${SERVER_JARFILE} \${DOWNLOAD_URL}

if [ ! -f server.properties ]; then
    echo -e "Downloading default server.properties"
    curl -o server.properties https://raw.githubusercontent.com/parkervcp/eggs/master/minecraft/java/server.properties
fi
`,
    installation_container: 'ghcr.io/parkervcp/installers:alpine',
    installation_entrypoint: 'ash',
    variables: JSON.stringify([
        {
            "name": "Minecraft Version",
            "description": "The version of minecraft to download.",
            "env_variable": "MINECRAFT_VERSION",
            "default_value": "latest",
            "user_viewable": true,
            "user_editable": true,
            "rules": "nullable|string|max:20"
        },
        {
            "name": "Server Jar File",
            "description": "The name of the server jarfile to run the server with.",
            "env_variable": "SERVER_JARFILE",
            "default_value": "server.jar",
            "user_viewable": true,
            "user_editable": true,
            "rules": "required|regex:\/^([\\w\\d._-]+)(\\.jar)$/"
        },
         {
            "name": "Build Number",
            "description": "The build number for the paper release.",
            "env_variable": "BUILD_NUMBER",
            "default_value": "latest",
            "user_viewable": true,
            "user_editable": true,
            "rules": "required|string|max:20"
        }
    ])
};

fetch(`http://localhost:3001/api/eggs/${eggId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
})
.then(res => res.json())
.then(data => console.log('Update result:', data))
.catch(err => console.error('Update failed:', err));

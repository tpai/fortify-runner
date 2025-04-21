import os
import git
import shutil
import docker
from flask import Flask, request, Response
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
auth = HTTPBasicAuth()

basic_auth_username = os.getenv("BASIC_AUTH_USERNAME", "admin")
basic_auth_password = os.getenv("BASIC_AUTH_PASSWORD", "secret")
git_ssh_key = os.getenv("GIT_SSH_KEY", "/path/to/ssh.key")
docker_username = os.getenv("DOCKER_USERNAME", "username")
docker_password = os.getenv("DOCKER_PASSWORD", "password")
docker_registry = os.getenv("DOCKER_REGISTRY", "registry_url")
scan_image = os.getenv("SCAN_IMAGE", "scan_image")
az_storage_url = os.getenv("AZ_STORAGE_URL", "az_storage_url")
az_storage_sas = os.getenv("AZ_STORAGE_SAS", "az_storage_sas")

users = {f"{basic_auth_username}": generate_password_hash(basic_auth_password)}


@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username


def launch_container(image_name, command, env_vars, volumes):
    client = docker.from_env()
    client.login(
        username=docker_username, password=docker_password, registry=docker_registry
    )

    try:
        container = client.containers.run(
            image_name,
            command=command,
            environment=env_vars,
            volumes=volumes,
            detach=True,
        )

        return container

    except docker.errors.ContainerError as e:
        raise Exception(f"ContainerError: {e}")

    except docker.errors.ImageNotFound as e:
        raise Exception(f"ImageNotFound: {e}")

    except docker.errors.APIError as e:
        raise Exception(f"APIError: {e}")


@app.route("/ping", methods=["GET"])
def api_ping():
    try:
        return {"status": "success"}
    except Exception as e:
        return {"status": "failure", "message": str(e)}, 500


@app.route("/test", methods=["GET"])
@auth.login_required
def api_test():
    try:
        command = "ls -al"
        container = launch_container("ubuntu:22.04", f'bash -c "ls -al"', None, None)
        return {"status": "success", "container_id": container.id}
    except Exception as e:
        return {"status": "failure", "message": str(e)}, 500


@app.route("/container/<string:container_id>", methods=["GET"])
@auth.login_required
def api_get_container_logs(container_id):
    client = docker.from_env()
    try:
        container = client.containers.get(container_id)

        def stream_logs():
            for line in container.logs(stream=True):
                yield line.strip().decode() + "\n"

        return Response(stream_logs(), mimetype="text/plain")
    except docker.errors.NotFound as e:
        return {"status": "failure", "message": "Container not found"}, 404
    except Exception as e:
        return {"status": "failure", "message": str(e)}, 500


@app.route("/scan", methods=["POST"])
@auth.login_required
def api_fortify_scan():
    data = request.get_json()
    image_name = data.get("image_name", scan_image)
    repo_url = data.get("repo_url", None)
    repo_name = data.get("repo_name", None)
    repo_type = data.get("repo_type", None)
    file_list = data.get("file_list", None)
    branch = data.get("branch", None)
    bypass_text = data.get("bypass_text", "")

    if not repo_url or not repo_name:
        raise ValueError("Both repo_url and repo_name must be well-defined")

    try:

        def stream_logs():
            yield f">git clone {repo_url}\n"
            git_ssh_identity_file = os.path.expanduser(git_ssh_key)
            git_ssh_cmd = f"ssh -i {git_ssh_identity_file}"
            repo_path = f"./scan/{repo_name}-{branch}"
            if os.path.exists(repo_path):
                shutil.rmtree(repo_path)
            with git.Git().custom_environment(GIT_SSH_COMMAND=git_ssh_cmd):
                git.Repo.clone_from(repo_url, repo_path)
                git_cmd = git.cmd.Git(repo_path)
                git_cmd.checkout(branch)

            volumes = {
                os.path.abspath(f"{repo_path}"): {"bind": f"/{repo_path}", "mode": "rw"}
            }

            with open(f"{repo_path}/bypass.txt", "w") as f:
                f.write(bypass_text)

            command = f"echo '>Create scan mission';"
            command += f"cd /{repo_path};"
            command += f"sourceanalyzer -b app -build-project {repo_name} -build-version {branch} "
            if file_list is None and repo_type == "python":
                command += f'-python-version 3 -python-path /usr/bin/python3 $(find /{repo_path} -name \\"*.py\\" -not -regex \\".*test.*\\");'
            elif file_list is None and repo_type == "golang":
                command += (
                    f'$(find /{repo_path} -name \\"*.go\\" -not -regex \\".*test.*\\");'
                )
            elif file_list is None and repo_type == "javascript":
                command += f'$(find /{repo_path} -regex \\".*.\(js\|ts\)$\\" -not -regex \\".*\(test\|enum\|public\).*\\");'

            if file_list is not None and repo_type == "python":
                command += f"-python-version 3 -python-path /usr/bin/python3 $(cat /{repo_path}/{file_list} | tr '\n' ' ');"
            elif file_list is not None and repo_type == "golang":
                command += f"$(cat /{repo_path}/{file_list} | tr '\n' ' ');"
            elif file_list is not None and repo_type == "javascript":
                command += f"$(cat /{repo_path}/{file_list} | tr '\n' ' ');"

            command += f"echo '>Show files';"
            command += f"sourceanalyzer -b app -show-files > sca_files;"
            command += f"cat sca_files;"
            command += f"cat sca_files | wc -l;"
            command += f"echo '>Run codebase scan';"
            command += f"sourceanalyzer -b app -scan -filter /{repo_path}/bypass.txt -f /{repo_path}/{repo_name}.fpr;"

            command += f"echo '>Generate report';"
            command += f"BIRTReportGenerator -template 'Developer Workbook' -source /{repo_path}/{repo_name}.fpr -format PDF -output /{repo_path}/report.pdf;"

            # command = f"echo '>Create scan mission'; ls -al {repo_path}; echo '>Run codebase scan'; cat /{repo_path}/bypass.txt; echo '>Generate report'; echo 'Report generated' > /{repo_path}/report.html" # placeholder
            container = launch_container(
                image_name, f'bash -c "{command}"', None, volumes
            )
            for line in container.logs(stream=True):
                yield line.strip().decode() + "\n"

            yield f">Upload report to storage\n"
            import requests
            from datetime import datetime

            headers = {
                "Content-Type": "application/pdf",
                "x-ms-date": datetime.utcnow().strftime("%a, %d %h %Y %H:%M:%S GMT"),
                "x-ms-blob-type": "BlockBlob",
            }
            with open(f"{repo_path}/report.pdf", "rb") as f:
                response = requests.put(
                    f"{az_storage_url}/{repo_name}_{branch}.pdf{az_storage_sas}",
                    headers=headers,
                    data=f,
                )
                yield f"HTTP status: {response.status_code}\n"
                if response.status_code >= 200 and response.status_code < 300:
                    yield f"Report link: {az_storage_url}/{repo_name}_{branch}.pdf\n"
                else:
                    yield f"Failed to upload report: {response.content}\n"

        return Response(stream_logs(), mimetype="text/plain")
    except Exception as e:
        return {"status": "failure", "message": str(e)}, 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

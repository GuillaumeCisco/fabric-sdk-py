import logging
import os
import time
import tarfile
import io

from hfc.protos.peer import chaincode_pb2
from hfc.util.utils import CC_TYPE_GOLANG, proto_str

_logger = logging.getLogger(__name__)

# https://jira.hyperledger.org/browse/FAB-7065
# ?page=com.atlassian.jira.plugin.system.issuetabpanels%3Acomment
# -tabpanel&showAll=true
def zeroTarInfo(tarinfo):

    tarinfo.uid = tarinfo.gid = 500
    tarinfo.mode = 100644
    tarinfo.mtime = 0
    tarinfo.pax_headers = {
        'atime': 0,
        'ctime': 0,
    }
    return tarinfo


# http://www.onicos.com/staff/iz/formats/gzip.html
# https://github.com/python/cpython/blob/master/Lib/tarfile.py#L420
class zeroTimeContextManager(object):
    def __enter__(self):
        self.real_time = time.time
        time.time = lambda: 0

    def __exit__(self, type, value, traceback):
        time.time = self.real_time


# TODO review, add others languages
class Package(object):

    @staticmethod
    def go_package(path):
        go_path = os.environ['GOPATH']
        if not path:
            raise ValueError('Missing chaincode path parameter in install proposal request')

        if not go_path:
            raise ValueError("No GOPATH env variable is found")

        proj_path = f'{go_path}/src/{path}'
        _logger.debug(f'Project path={proj_path}')

        if not os.listdir(proj_path):
            raise ValueError('No chaincode file found!')

        tar_stream = io.BytesIO()
        with zeroTimeContextManager():
            dist = tarfile.open(fileobj=tar_stream, mode='w|gz')
            for dir_path, _, file_names in os.walk(proj_path):
                for filename in file_names:
                    file_path = os.path.join(dir_path, filename)

                    with open(file_path, mode='rb') as f:
                        arcname = os.path.relpath(file_path, go_path)
                        tarinfo = dist.gettarinfo(file_path, arcname)
                        tarinfo = zeroTarInfo(tarinfo)
                        dist.addfile(tarinfo, f)

            dist.close()
            tar_stream.seek(0)
            code_content = tar_stream.read()

        if code_content:
            return code_content
        else:
            raise ValueError('No chaincode found')

    @staticmethod
    def fromDirectory(request):
        _logger.debug(f"Package.fromDirectory - entry - {request['name']}, {request['version']}, {request['path']}, {request['type']}")

        # TODO validate

        if request['type'] == CC_TYPE_GOLANG:
            codePackage = Package.go_package(request['path'])

            chaincodeDeploymentSpec = chaincode_pb2.ChaincodeDeploymentSpec()
            chaincodeDeploymentSpec.chaincode_spec.type = chaincode_pb2.ChaincodeSpec.Type.Value(proto_str(request['type']))
            chaincodeDeploymentSpec.chaincode_spec.chaincode_id.name = proto_str(request['name'])
            chaincodeDeploymentSpec.chaincode_spec.chaincode_id.path = proto_str(request['path'])  # TODO handle windows
            chaincodeDeploymentSpec.chaincode_spec.chaincode_id.version = proto_str(request['version'])

            chaincodeDeploymentSpec.code_package = codePackage

            return chaincodeDeploymentSpec

        else:
            raise ValueError('Currently only support install GOLANG chaincode')

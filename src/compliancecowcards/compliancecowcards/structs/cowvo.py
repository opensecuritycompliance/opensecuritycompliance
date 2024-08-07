#!/usr/local/bin/python
from typing import Optional, Any, TypeVar, Type, cast, List, Callable
from compliancecowcards.utils import cowdictutils
from datetime import datetime
from dateutil import parser


T = TypeVar("T")


def from_str(x: Any) -> str:
    assert isinstance(x, str)
    return x


def from_none(x: Any) -> Any:
    assert x is None
    return x


def from_union(fs, x):
    for f in fs:
        try:
            return f(x)
        except:
            pass
    assert False


def from_int(x: Any) -> int:
    assert isinstance(x, int) and not isinstance(x, bool)
    return x


def to_class(c: Type[T], x: Any) -> dict:
    if isinstance(x, c):
        return cast(Any, x).to_dict()
    return None


def from_list(f: Callable[[Any], T], x: Any) -> List[T]:
    if isinstance(x, list):
        return [f(y) for y in x]
    return None


class CredentialBase:
    cred_guid: Optional[str]
    cred_type: Optional[str]
    source_guid: Optional[str]
    source_type: Optional[str]
    user_id: Optional[str]

    def __init__(
        self,
        cred_guid: Optional[str],
        cred_type: Optional[str],
        source_guid: Optional[str],
        source_type: Optional[str],
        user_id: Optional[str],
    ) -> None:
        self.cred_guid = cred_guid
        self.cred_type = cred_type
        self.source_guid = source_guid
        self.source_type = source_type
        self.user_id = user_id

    @staticmethod
    def from_dict(obj: Any) -> "CredentialBase":
        cred_guid, cred_type, source_guid, source_type, user_id = (
            None,
            None,
            None,
            None,
            None,
        )
        if isinstance(obj, dict):
            if cowdictutils.is_valid_key(obj, "credguid"):
                cred_guid = from_union([from_str, from_none], obj.get("credguid"))
            if cowdictutils.is_valid_key(obj, "credtype"):
                cred_type = from_union([from_str, from_none], obj.get("credtype"))
            if cowdictutils.is_valid_key(obj, "sourceguid"):
                source_guid = from_union([from_str, from_none], obj.get("sourceguid"))
            if cowdictutils.is_valid_key(obj, "sourcetype"):
                source_type = from_union([from_str, from_none], obj.get("sourcetype"))
            if cowdictutils.is_valid_key(obj, "userID"):
                user_id = from_union([from_str, from_none], obj.get("userID"))
        return CredentialBase(cred_guid, cred_type, source_guid, source_type, user_id)

    def to_dict(self) -> dict:
        result: dict = {}
        result["credguid"] = from_union([from_str, from_none], self.cred_guid)
        result["credtype"] = from_union([from_str, from_none], self.cred_type)
        result["sourceguid"] = from_union([from_str, from_none], self.source_guid)
        result["sourcetype"] = from_union([from_str, from_none], self.source_type)
        result["userID"] = from_union([from_str, from_none], self.user_id)
        return result


def credential_base_from_dict(s: Any) -> CredentialBase:
    return CredentialBase.from_dict(s)


def credential_base_to_dict(x: CredentialBase) -> Any:
    return to_class(CredentialBase, x)


class Credential(CredentialBase):
    id: Optional[str]
    password_hash: None
    password: Optional[str]
    login_url: Optional[str]
    ssh_private_key: None
    cred_tags: None
    other_cred_info: None
    cred_guid: Optional[str]
    cred_type: Optional[str]
    source_guid: Optional[str]
    source_type: Optional[str]
    user_id: Optional[str]

    def __init__(
        self,
        id: Optional[str],
        password_hash: None,
        password: Optional[str],
        login_url: Optional[str],
        ssh_private_key: None,
        cred_tags: None,
        other_cred_info: None,
        cred_guid: Optional[str],
        cred_type: Optional[str],
        source_guid: Optional[str],
        source_type: Optional[str],
        user_id: Optional[str],
    ) -> None:
        self.id = id
        self.password_hash = password_hash
        self.password = password
        self.login_url = login_url
        self.ssh_private_key = ssh_private_key
        self.cred_tags = cred_tags
        self.other_cred_info = other_cred_info
        self.cred_guid = cred_guid
        self.cred_type = cred_type
        self.source_guid = source_guid
        self.source_type = source_type
        self.user_id = user_id

    @staticmethod
    def from_dict(obj: Any) -> "Credential":
        (
            id,
            password_hash,
            password,
            login_url,
            ssh_private_key,
            cred_tags,
            other_cred_info,
        ) = (
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        cred_guid, cred_type, source_guid, source_type, user_id = (
            None,
            None,
            None,
            None,
            None,
        )
        if isinstance(obj, dict):
            if cowdictutils.is_valid_key(obj, "id"):
                id = from_union([from_str, from_none], obj.get("id"))
            if cowdictutils.is_valid_key(obj, "passwordhash"):
                password_hash = obj.get("passwordhash")
            if cowdictutils.is_valid_key(obj, "passwordstring"):
                password = from_union([from_str, from_none], obj.get("passwordstring"))
            if cowdictutils.is_valid_key(obj, "loginurl"):
                login_url = from_union([from_str, from_none], obj.get("loginurl"))
            if cowdictutils.is_valid_key(obj, "sshprivatekey"):
                ssh_private_key = obj.get("sshprivatekey")
            if cowdictutils.is_valid_key(obj, "credtags"):
                cred_tags = obj.get("credtags")
            if cowdictutils.is_valid_key(obj, "othercredinfomap"):
                other_cred_info = obj.get("othercredinfomap")
            if cowdictutils.is_valid_key(obj, "credguid"):
                cred_guid = from_union([from_str, from_none], obj.get("credguid"))
            if cowdictutils.is_valid_key(obj, "credtype"):
                cred_type = from_union([from_str, from_none], obj.get("credtype"))
            if cowdictutils.is_valid_key(obj, "sourceguid"):
                source_guid = from_union([from_str, from_none], obj.get("sourceguid"))
            if cowdictutils.is_valid_key(obj, "sourcetype"):
                source_type = from_union([from_str, from_none], obj.get("sourcetype"))
            if cowdictutils.is_valid_key(obj, "userID"):
                user_id = from_union([from_str, from_none], obj.get("userID"))
        return Credential(
            id,
            password_hash,
            password,
            login_url,
            ssh_private_key,
            cred_tags,
            other_cred_info,
            cred_guid,
            cred_type,
            source_guid,
            source_type,
            user_id,
        )

    def to_dict(self) -> dict:
        result: dict = {}
        result["id"] = from_union([from_str, from_none], self.id)
        result["passwordhash"] = self.password_hash
        result["passwordstring"] = from_union([from_str, from_none], self.password)
        result["loginurl"] = from_union([from_str, from_none], self.login_url)
        result["sshprivatekey"] = self.ssh_private_key
        result["credtags"] = self.cred_tags
        result["othercredinfomap"] = self.other_cred_info
        result["credguid"] = from_union([from_str, from_none], self.cred_guid)
        result["credtype"] = from_union([from_str, from_none], self.cred_type)
        result["sourceguid"] = from_union([from_str, from_none], self.source_guid)
        result["sourcetype"] = from_union([from_str, from_none], self.source_type)
        result["userID"] = from_union([from_str, from_none], self.user_id)
        return result


def credential_from_dict(s: Any) -> Credential:
    return Credential.from_dict(s)


def credential_to_dict(x: Credential) -> Any:
    return to_class(Credential, x)


class ClusterInfo:
    cluster_name: Optional[str]
    cluster_members: None

    def __init__(self, cluster_name: Optional[str], cluster_members: None) -> None:
        self.cluster_name = cluster_name
        self.cluster_members = cluster_members

    @staticmethod
    def from_dict(obj: Any) -> "ClusterInfo":
        cluster_name, cluster_members = None, None
        if isinstance(obj, dict):
            if cowdictutils.is_valid_key(obj, "clustername"):
                cluster_name = from_union([from_str, from_none], obj.get("clustername"))
            if cowdictutils.is_valid_key(obj, "clustermembers"):
                cluster_members = obj.get("clustermembers")
        return ClusterInfo(cluster_name, cluster_members)

    def to_dict(self) -> dict:
        result: dict = {}
        result["clustername"] = from_union([from_str, from_none], self.cluster_name)
        result["clustermembers"] = self.cluster_members
        return result


class OSInfo:
    os_distribution: Optional[str]
    os_kernel_level: Optional[str]
    os_patch_level: Optional[str]

    def __init__(
        self,
        os_distribution: Optional[str],
        os_kernel_level: Optional[str],
        os_patch_level: Optional[str],
    ) -> None:
        self.os_distribution = os_distribution
        self.os_kernel_level = os_kernel_level
        self.os_patch_level = os_patch_level

    @staticmethod
    def from_dict(obj: Any) -> "OSInfo":
        os_distribution, os_kernel_level, os_patch_level = None, None, None
        if isinstance(obj, dict):
            if cowdictutils.is_valid_key(obj, "osdistribution"):
                os_distribution = from_union(
                    [from_str, from_none], obj.get("osdistribution")
                )
            if cowdictutils.is_valid_key(obj, "oskernellevel"):
                os_kernel_level = from_union(
                    [from_str, from_none], obj.get("oskernellevel")
                )
            if cowdictutils.is_valid_key(obj, "ospatchlevel"):
                os_patch_level = from_union(
                    [from_str, from_none], obj.get("ospatchlevel")
                )
        return OSInfo(os_distribution, os_kernel_level, os_patch_level)

    def to_dict(self) -> dict:
        result: dict = {}
        result["osdistribution"] = from_union(
            [from_str, from_none], self.os_distribution
        )
        result["oskernellevel"] = from_union(
            [from_str, from_none], self.os_kernel_level
        )
        result["ospatchlevel"] = from_union([from_str, from_none], self.os_patch_level)
        return result


class OtherInfo:
    cpu: Optional[int]
    gb_memory: Optional[int]

    def __init__(self, cpu: Optional[int], gb_memory: Optional[int]) -> None:
        self.cpu = cpu
        self.gb_memory = gb_memory

    @staticmethod
    def from_dict(obj: Any) -> "OtherInfo":
        cpu, gb_memory = None, None
        if isinstance(obj, dict):
            if cowdictutils.is_valid_key(obj, "cpu"):
                cpu = from_union([from_int, from_none], obj.get("cpu"))
            if cowdictutils.is_valid_key(obj, "memory_gb"):
                gb_memory = from_union([from_int, from_none], obj.get("memory_gb"))
        return OtherInfo(cpu, gb_memory)

    def to_dict(self) -> dict:
        result: dict = {}
        result["cpu"] = from_union([from_int, from_none], self.cpu)
        result["memory_gb"] = from_union([from_int, from_none], self.gb_memory)
        return result


class ServerBase:
    server_guid: Optional[str]
    server_name: Optional[str]
    application_guid: Optional[str]
    server_type: Optional[str]
    server_url: Optional[str]
    server_host_name: Optional[str]

    def __init__(
        self,
        server_guid: Optional[str],
        server_name: Optional[str],
        application_guid: Optional[str],
        server_type: Optional[str],
        server_url: Optional[str],
        server_host_name: Optional[str],
    ) -> None:
        self.server_guid = server_guid
        self.server_name = server_name
        self.application_guid = application_guid
        self.server_type = server_type
        self.server_url = server_url
        self.server_host_name = server_host_name

    @staticmethod
    def from_dict(obj: Any) -> "ServerBase":
        (
            server_guid,
            server_name,
            application_guid,
            server_type,
            server_url,
            server_host_name,
        ) = (
            None,
            None,
            None,
            None,
            None,
            None,
        )
        if isinstance(obj, dict):
            if cowdictutils.is_valid_key(obj, "ServerGUID"):
                server_guid = from_union([from_str, from_none], obj.get("ServerGUID"))
            if cowdictutils.is_valid_key(obj, "servername"):
                server_name = from_union([from_str, from_none], obj.get("servername"))
            if cowdictutils.is_valid_key(obj, "appid"):
                application_guid = from_union([from_str, from_none], obj.get("appid"))
            if cowdictutils.is_valid_key(obj, "servertype"):
                server_type = from_union([from_str, from_none], obj.get("servertype"))
            if cowdictutils.is_valid_key(obj, "serverurl"):
                server_url = from_union([from_str, from_none], obj.get("serverurl"))
            if cowdictutils.is_valid_key(obj, "serverhostname"):
                server_host_name = from_union(
                    [from_str, from_none], obj.get("serverhostname")
                )
        return ServerBase(
            server_guid,
            server_name,
            application_guid,
            server_type,
            server_url,
            server_host_name,
        )

    def to_dict(self) -> dict:
        result: dict = {}
        result["ServerGUID"] = from_union([from_str, from_none], self.server_guid)
        result["servername"] = from_union([from_str, from_none], self.server_name)
        result["appid"] = from_union([from_str, from_none], self.application_guid)
        result["servertype"] = from_union([from_str, from_none], self.server_type)
        result["serverurl"] = from_union([from_str, from_none], self.server_url)
        result["serverhostname"] = from_union(
            [from_str, from_none], self.server_host_name
        )
        return result


def server_base_from_dict(s: Any) -> ServerBase:
    return ServerBase.from_dict(s)


def server_base_to_dict(x: ServerBase) -> Any:
    return to_class(ServerBase, x)


class ServerAbstract(ServerBase):
    id: Optional[str]
    server_tags: None
    server_boot_seq: Optional[int]
    action_type: Optional[str]
    os_info: Optional[OSInfo]
    i_pv4_addresses: None
    volumes: None
    other_info: Optional[OtherInfo]
    cluster_info: Optional[ClusterInfo]
    servers: None
    server_guid: Optional[str]
    server_name: Optional[str]
    application_guid: Optional[str]
    server_type: Optional[str]
    server_url: Optional[str]
    server_host_name: Optional[str]

    def __init__(
        self,
        id: Optional[str],
        server_tags: None,
        server_boot_seq: Optional[int],
        action_type: Optional[str],
        os_info: Optional[OSInfo],
        i_pv4_addresses: None,
        volumes: None,
        other_info: Optional[OtherInfo],
        cluster_info: Optional[ClusterInfo],
        servers: None,
        server_guid: Optional[str],
        server_name: Optional[str],
        application_guid: Optional[str],
        server_type: Optional[str],
        server_url: Optional[str],
        server_host_name: Optional[str],
    ) -> None:
        self.id = id
        self.server_tags = server_tags
        self.server_boot_seq = server_boot_seq
        self.action_type = action_type
        self.os_info = os_info
        self.i_pv4_addresses = i_pv4_addresses
        self.volumes = volumes
        self.other_info = other_info
        self.cluster_info = cluster_info
        self.servers = servers
        self.server_guid = server_guid
        self.server_name = server_name
        self.application_guid = application_guid
        self.server_type = server_type
        self.server_url = server_url
        self.server_host_name = server_host_name

    @staticmethod
    def from_dict(obj: Any) -> "ServerAbstract":
        (
            id,
            server_tags,
            server_boot_seq,
            action_type,
            os_info,
            i_pv4_addresses,
            volumes,
            other_info,
            cluster_info,
            servers,
        ) = (None, None, None, None, None, None, None, None, None, None)
        (
            server_guid,
            server_name,
            application_guid,
            server_type,
            server_url,
            server_host_name,
        ) = (
            None,
            None,
            None,
            None,
            None,
            None,
        )
        if isinstance(obj, dict):
            if cowdictutils.is_valid_key(obj, "id"):
                id = from_union([from_str, from_none], obj.get("id"))
            if cowdictutils.is_valid_key(obj, "servertags"):
                server_tags = obj.get("servertags")
            if cowdictutils.is_valid_key(obj, "serverbootseq"):
                server_boot_seq = from_union(
                    [from_int, from_none], obj.get("serverbootseq")
                )
            if cowdictutils.is_valid_key(obj, "actiontype"):
                action_type = from_union([from_str, from_none], obj.get("actiontype"))
            if cowdictutils.is_valid_key(obj, "osinfo"):
                os_info = from_union([OSInfo.from_dict, from_none], obj.get("osinfo"))
            if cowdictutils.is_valid_key(obj, "ipv4addresses"):
                i_pv4_addresses = obj.get("ipv4addresses")
            if cowdictutils.is_valid_key(obj, "volumes"):
                volumes = obj.get("volumes")
            if cowdictutils.is_valid_key(obj, "otherinfo"):
                other_info = from_union(
                    [OtherInfo.from_dict, from_none], obj.get("otherinfo")
                )
            if cowdictutils.is_valid_key(obj, "clusterinfo"):
                cluster_info = from_union(
                    [ClusterInfo.from_dict, from_none], obj.get("clusterinfo")
                )
            if cowdictutils.is_valid_key(obj, "servers"):
                servers = obj.get("servers")
            if cowdictutils.is_valid_key(obj, "ServerGUID"):
                server_guid = from_union([from_str, from_none], obj.get("ServerGUID"))
            if cowdictutils.is_valid_key(obj, "servername"):
                server_name = from_union([from_str, from_none], obj.get("servername"))
            if cowdictutils.is_valid_key(obj, "appid"):
                application_guid = from_union([from_str, from_none], obj.get("appid"))
            if cowdictutils.is_valid_key(obj, "servertype"):
                server_type = from_union([from_str, from_none], obj.get("servertype"))
            if cowdictutils.is_valid_key(obj, "serverurl"):
                server_url = from_union([from_str, from_none], obj.get("serverurl"))
            if cowdictutils.is_valid_key(obj, "serverhostname"):
                server_host_name = from_union(
                    [from_str, from_none], obj.get("serverhostname")
                )
        return ServerAbstract(
            id,
            server_tags,
            server_boot_seq,
            action_type,
            os_info,
            i_pv4_addresses,
            volumes,
            other_info,
            cluster_info,
            servers,
            server_guid,
            server_name,
            application_guid,
            server_type,
            server_url,
            server_host_name,
        )

    def to_dict(self) -> dict:
        result: dict = {}
        result["id"] = from_union([from_str, from_none], self.id)
        result["servertags"] = self.server_tags
        result["serverbootseq"] = from_union(
            [from_int, from_none], self.server_boot_seq
        )
        result["actiontype"] = from_union([from_str, from_none], self.action_type)
        result["osinfo"] = from_union(
            [lambda x: to_class(OSInfo, x), from_none], self.os_info
        )
        result["ipv4addresses"] = self.i_pv4_addresses
        result["volumes"] = self.volumes
        result["otherinfo"] = from_union(
            [lambda x: to_class(OtherInfo, x), from_none], self.other_info
        )
        result["clusterinfo"] = from_union(
            [lambda x: to_class(ClusterInfo, x), from_none], self.cluster_info
        )
        result["servers"] = self.servers
        result["ServerGUID"] = from_union([from_str, from_none], self.server_guid)
        result["servername"] = from_union([from_str, from_none], self.server_name)
        result["appid"] = from_union([from_str, from_none], self.application_guid)
        result["servertype"] = from_union([from_str, from_none], self.server_type)
        result["serverurl"] = from_union([from_str, from_none], self.server_url)
        result["serverhostname"] = from_union(
            [from_str, from_none], self.server_host_name
        )
        return result


def server_abstract_from_dict(s: Any) -> ServerAbstract:
    return ServerAbstract.from_dict(s)


def server_abstract_to_dict(x: ServerAbstract) -> Any:
    return to_class(ServerAbstract, x)


class AppBase:
    application_name: Optional[str]
    application_guid: Optional[str]
    app_group_guid: Optional[str]
    application_url: Optional[str]
    application_port: Optional[int]
    other_info: None

    def __init__(
        self,
        application_name: Optional[str],
        application_guid: Optional[str],
        app_group_guid: Optional[str],
        application_url: Optional[str],
        application_port: Optional[int],
        other_info: None,
    ) -> None:
        self.application_name = application_name
        self.application_guid = application_guid
        self.app_group_guid = app_group_guid
        self.application_url = application_url
        self.application_port = application_port
        self.other_info = other_info

    @staticmethod
    def from_dict(obj: Any) -> "AppBase":
        (
            application_name,
            application_guid,
            app_group_guid,
            application_url,
            application_port,
            other_info,
        ) = (None, None, None, None, None, None)
        if isinstance(obj, dict):
            if cowdictutils.is_valid_key(obj, "appName"):
                application_name = from_union([from_str, from_none], obj.get("appName"))
            if cowdictutils.is_valid_key(obj, "appid"):
                application_guid = from_union([from_str, from_none], obj.get("appid"))
            if cowdictutils.is_valid_key(obj, "appGroupId"):
                app_group_guid = from_union(
                    [from_str, from_none], obj.get("appGroupId")
                )
            if cowdictutils.is_valid_key(obj, "appurl"):
                application_url = from_union([from_str, from_none], obj.get("appurl"))
            if cowdictutils.is_valid_key(obj, "application_url"):
                application_url = obj["application_url"]
            if cowdictutils.is_valid_key(obj, "AppURL"):
                application_url = obj["AppURL"]
            if cowdictutils.is_valid_key(obj, "appURL"):
                application_url = obj["appURL"]
            if cowdictutils.is_valid_key(obj, "application_port"):
                application_port = int(obj["application_port"])
            if cowdictutils.is_valid_key(obj, "appPort"):
                application_port = int(obj["appPort"])
            if cowdictutils.is_valid_key(obj, "appport"):
                application_port = int(obj["appport"])
            if cowdictutils.is_valid_key(obj, "AppPort"):
                application_port = int(obj["AppPort"])
            if cowdictutils.is_valid_key(obj, "Port"):
                application_port = int(obj["Port"])
            if cowdictutils.is_valid_key(obj, "port"):
                application_port = int(obj["port"])
            if cowdictutils.is_valid_key(obj, "otherinfo"):
                other_info = obj.get("otherinfo")
        return AppBase(
            application_name,
            application_guid,
            app_group_guid,
            application_url,
            application_port,
            other_info,
        )

    def to_dict(self) -> dict:
        result: dict = {}
        result["appName"] = from_union([from_str, from_none], self.application_name)
        result["appid"] = from_union([from_str, from_none], self.application_guid)
        result["appGroupId"] = from_union([from_str, from_none], self.app_group_guid)
        result["appurl"] = from_union([from_str, from_none], self.application_url)
        result["port"] = from_union([from_str, from_none], self.application_port)
        result["otherinfo"] = self.other_info
        return result


def app_base_from_dict(s: Any) -> AppBase:
    return AppBase.from_dict(s)


def app_base_to_dict(x: AppBase) -> Any:
    return to_class(AppBase, x)


class AppAbstract(AppBase):
    id: Optional[str]
    app_sequence: Optional[int]
    app_tags: None
    action_type: Optional[str]
    app_objects: None
    servers: None
    application_name: Optional[str]
    application_guid: Optional[str]
    app_group_guid: Optional[str]
    application_url: Optional[str]
    application_port: Optional[int]
    other_info: None
    user_defined_credentials: None
    linked_applications: None

    def __init__(
        self,
        id: Optional[str],
        app_sequence: Optional[int],
        app_tags: None,
        action_type: Optional[str],
        app_objects: None,
        servers: None,
        application_name: Optional[str],
        application_guid: Optional[str],
        app_group_guid: Optional[str],
        application_url: Optional[str],
        application_port: Optional[int],
        other_info: None,
        user_defined_credentials: None,
        linked_applications: None,
    ) -> None:
        self.id = id
        self.app_sequence = app_sequence
        self.app_tags = app_tags
        self.action_type = action_type
        self.app_objects = app_objects
        self.servers = servers
        self.application_name = application_name
        self.application_guid = application_guid
        self.app_group_guid = app_group_guid
        self.application_url = application_url
        self.other_info = other_info
        self.user_defined_credentials = user_defined_credentials
        self.linked_applications = linked_applications
        self.application_port = application_port

    @staticmethod
    def from_dict(obj: Any) -> "AppAbstract":
        id, app_sequence, app_tags, action_type, app_objects, servers = (
            None,
            None,
            None,
            None,
            None,
            None,
        )
        (
            application_name,
            application_guid,
            app_group_guid,
            application_url,
            application_port,
            other_info,
            user_defined_credentials,
            linked_applications,
        ) = (None, None, None, None, None, None, None, None)
        if isinstance(obj, dict):
            if cowdictutils.is_valid_key(obj, "id"):
                id = from_union([from_str, from_none], obj.get("id"))
            if cowdictutils.is_valid_key(obj, "appSequence"):
                app_sequence = from_union([from_int, from_none], obj.get("appSequence"))
            if cowdictutils.is_valid_key(obj, "appTags"):
                app_tags = obj.get("appTags")
            if cowdictutils.is_valid_key(obj, "actiontype"):
                action_type = from_union([from_str, from_none], obj.get("actiontype"))
            if cowdictutils.is_valid_key(obj, "AppObjects"):
                app_objects = obj.get("AppObjects")
            if cowdictutils.is_valid_key(obj, "servers"):
                servers = obj.get("servers")
            if cowdictutils.is_valid_key(obj, "appName"):
                application_name = from_union([from_str, from_none], obj.get("appName"))
            if cowdictutils.is_valid_key(obj, "appid"):
                application_guid = from_union([from_str, from_none], obj.get("appid"))
            if cowdictutils.is_valid_key(obj, "appGroupId"):
                app_group_guid = from_union(
                    [from_str, from_none], obj.get("appGroupId")
                )
            if cowdictutils.is_valid_key(obj, "appurl"):
                application_url = from_union([from_str, from_none], obj.get("appurl"))
            if cowdictutils.is_valid_key(obj, "application_url"):
                application_url = obj["application_url"]
            if cowdictutils.is_valid_key(obj, "AppURL"):
                application_url = obj["AppURL"]
            if cowdictutils.is_valid_key(obj, "appURL"):
                application_url = obj["appURL"]
            if cowdictutils.is_valid_key(obj, "application_port"):
                application_port = int(obj["application_port"])
            if cowdictutils.is_valid_key(obj, "appPort"):
                application_port = int(obj["appPort"])
            if cowdictutils.is_valid_key(obj, "appport"):
                application_port = int(obj["appport"])
            if cowdictutils.is_valid_key(obj, "AppPort"):
                application_port = int(obj["AppPort"])
            if cowdictutils.is_valid_key(obj, "Port"):
                application_port = int(obj["Port"])
            if cowdictutils.is_valid_key(obj, "port"):
                application_port = int(obj["port"])
            if cowdictutils.is_valid_key(obj, "otherinfo"):
                other_info = obj.get("otherinfo")
            if cowdictutils.is_valid_key(obj, "userDefinedCredentials"):
                user_defined_credentials = obj.get("userDefinedCredentials")
            if cowdictutils.is_valid_key(obj, "linkedApplications"):
                linked_applications = obj.get("linkedApplications")
        return AppAbstract(
            id,
            app_sequence,
            app_tags,
            action_type,
            app_objects,
            servers,
            application_name,
            application_guid,
            app_group_guid,
            application_url,
            application_port,
            other_info,
            user_defined_credentials,
            linked_applications,
        )

    def to_dict(self) -> dict:
        result: dict = {}
        result["id"] = from_union([from_str, from_none], self.id)
        result["appSequence"] = from_union([from_int, from_none], self.app_sequence)
        result["appTags"] = self.app_tags
        result["actiontype"] = from_union([from_str, from_none], self.action_type)
        result["AppObjects"] = self.app_objects
        result["servers"] = self.servers
        result["appName"] = from_union([from_str, from_none], self.application_name)
        result["appid"] = from_union([from_str, from_none], self.application_guid)
        result["appGroupId"] = from_union([from_str, from_none], self.app_group_guid)
        result["appurl"] = from_union([from_str, from_none], self.application_url)
        result["port"] = self.application_port
        result["otherinfo"] = self.other_info
        result["userDefinedCredentials"] = self.user_defined_credentials
        result["linkedApplications"] = self.linked_applications
        return result


def app_abstract_from_dict(s: Any) -> AppAbstract:
    return AppAbstract.from_dict(s)


def app_abstract_to_dict(x: AppAbstract) -> Any:
    return to_class(AppAbstract, x)


class MetaDataTemplate:
    rule_guid: Optional[str]
    rule_task_guid: Optional[str]
    control_id: Optional[str]
    plan_execution_guid: Optional[str]

    def __init__(
        self,
        rule_guid: Optional[str],
        rule_task_guid: Optional[str],
        control_id: Optional[str],
        plan_execution_guid: Optional[str],
    ) -> None:
        self.rule_guid = rule_guid
        self.rule_task_guid = rule_task_guid
        self.control_id = control_id
        self.plan_execution_guid = plan_execution_guid

    @staticmethod
    def from_dict(obj: Any) -> "MetaDataTemplate":
        rule_guid, rule_task_guid, control_id, plan_execution_guid = (
            None,
            None,
            None,
            None,
        )
        if isinstance(obj, dict):
            if cowdictutils.is_valid_key(obj, "RuleGUID"):
                rule_guid = from_union([from_str, from_none], obj.get("RuleGUID"))
            if cowdictutils.is_valid_key(obj, "RuleTaskGUID"):
                rule_task_guid = from_union(
                    [from_str, from_none], obj.get("RuleTaskGUID")
                )
            if cowdictutils.is_valid_key(obj, "ControlID"):
                control_id = from_union([from_str, from_none], obj.get("ControlID"))
            if cowdictutils.is_valid_key(obj, "PlanExecutionGUID"):
                plan_execution_guid = from_union(
                    [from_str, from_none], obj.get("PlanExecutionGUID")
                )
        return MetaDataTemplate(
            rule_guid, rule_task_guid, control_id, plan_execution_guid
        )

    def to_dict(self) -> dict:
        result: dict = {}
        result["RuleGUID"] = from_union([from_str, from_none], self.rule_guid)
        result["RuleTaskGUID"] = from_union([from_str, from_none], self.rule_task_guid)
        result["ControlID"] = from_union([from_str, from_none], self.control_id)
        result["PlanExecutionGUID"] = from_union(
            [from_str, from_none], self.plan_execution_guid
        )
        return result


def meta_data_template_from_dict(s: Any) -> MetaDataTemplate:
    return MetaDataTemplate.from_dict(s)


def meta_data_template_to_dict(x: MetaDataTemplate) -> Any:
    return to_class(MetaDataTemplate, x)


class TaskOutputs:
    outputs: Optional[dict]

    def __init__(self, outputs: Optional[dict]) -> None:
        self.outputs = outputs

    @staticmethod
    def from_dict(obj: Any) -> "TaskOutputs":
        outputs = None
        if isinstance(obj, dict):
            outputs = obj
        return TaskOutputs(outputs)

    def to_dict(self) -> dict:
        result: dict = {}
        result["Outputs"] = self.outputs
        return result


def task_outputs_from_dict(s: Any) -> TaskOutputs:
    return TaskOutputs.from_dict(s)


def task_outputs_to_dict(x: TaskOutputs) -> Any:
    return to_class(TaskOutputs, x)


class ObjectTemplate:
    app: AppAbstract
    server: ServerAbstract
    credentials: List[Credential]

    def __init__(
        self,
        app: AppAbstract,
        server: ServerAbstract,
        credentials: List[Credential],
    ) -> None:
        self.app = app
        self.server = server
        self.credentials = credentials

    @staticmethod
    def from_dict(obj: Any) -> "ObjectTemplate":
        app, server, credentials = None, None, None
        if isinstance(obj, dict):
            if cowdictutils.is_valid_key(obj, "App"):
                app = app_abstract_from_dict(obj.get("App"))
            if cowdictutils.is_valid_key(obj, "app"):
                app = app_abstract_from_dict(obj.get("app"))
            if cowdictutils.is_valid_key(obj, "Server"):
                server = server_abstract_from_dict(obj.get("Server"))
            if cowdictutils.is_valid_key(obj, "server"):
                server = server_abstract_from_dict(obj.get("server"))
            if cowdictutils.is_valid_array(obj, "Credentials"):
                credentials = from_list(Credential.from_dict, obj.get("Credentials"))
            if cowdictutils.is_valid_array(obj, "credentials"):
                credentials = from_list(Credential.from_dict, obj.get("credentials"))
        return ObjectTemplate(app, server, credentials)

    def to_dict(self) -> dict:
        result: dict = {}
        result["App"] = app_abstract_to_dict(self.app)
        result["Server"] = server_abstract_to_dict(self.server)
        result["Credentials"] = from_list(
            lambda x: to_class(Credential, x), self.credentials
        )
        return result


def object_template_from_dict(s: Any) -> ObjectTemplate:
    return ObjectTemplate.from_dict(s)


def object_template_to_dict(x: ObjectTemplate) -> Any:
    return to_class(ObjectTemplate, x)


class SystemInputs:
    user_object: ObjectTemplate
    system_objects: List[ObjectTemplate]
    meta_data: MetaDataTemplate

    def __init__(
        self,
        user_object: ObjectTemplate,
        system_objects: List[ObjectTemplate],
        meta_data: MetaDataTemplate,
    ) -> None:
        self.user_object = user_object
        self.system_objects = system_objects
        self.meta_data = meta_data

    @staticmethod
    def from_dict(obj: Any) -> "SystemInputs":
        user_object, system_objects, meta_data = None, None, None
        if isinstance(obj, dict):
            if cowdictutils.is_valid_key(obj, "UserObject"):
                user_object = object_template_from_dict(obj.get("UserObject"))
            if cowdictutils.is_valid_array(obj, "SystemObjects"):
                system_objects = from_list(
                    ObjectTemplate.from_dict, obj.get("SystemObjects")
                )
            if cowdictutils.is_valid_key(obj, "MetaData"):
                meta_data = meta_data_template_from_dict(obj.get("MetaData"))
        return SystemInputs(user_object, system_objects, meta_data)

    def to_dict(self) -> dict:
        result: dict = {}
        result["UserObject"] = object_template_to_dict(self.user_object)
        result["SystemObjects"] = from_list(
            lambda x: to_class(ObjectTemplate, x), self.system_objects
        )
        result["MetaData"] = meta_data_template_to_dict(self.meta_data)
        return result


def system_inputs_from_dict(s: Any) -> SystemInputs:
    return SystemInputs.from_dict(s)


def system_inputs_to_dict(x: SystemInputs) -> Any:
    return to_class(SystemInputs, x)


class PathConfiguration:
    tasks_path: Optional[str]
    rules_path: Optional[str]
    execution_path: Optional[str]

    def __init__(
        self,
        tasks_path: Optional[str],
        rules_path: Optional[str],
        execution_path: Optional[str],
    ) -> None:
        self.tasks_path = tasks_path
        self.rules_path = rules_path
        self.execution_path = execution_path

    @staticmethod
    def from_dict(obj: Any) -> "PathConfiguration":
        assert isinstance(obj, dict)
        tasks_path = from_union([from_str, from_none], obj.get("tasksPath"))
        rules_path = from_union([from_str, from_none], obj.get("rulesPath"))
        execution_path = from_union([from_str, from_none], obj.get("executionPath"))
        return PathConfiguration(tasks_path, rules_path, execution_path)

    def to_dict(self) -> dict:
        result: dict = {}
        result["tasksPath"] = from_union([from_str, from_none], self.tasks_path)
        result["rulesPath"] = from_union([from_str, from_none], self.rules_path)
        result["executionPath"] = from_union([from_str, from_none], self.execution_path)
        return result


class PolicyCowConfig:
    version: Optional[str]
    path_configuration: Optional[PathConfiguration]

    def __init__(
        self, version: Optional[str], path_configuration: Optional[PathConfiguration]
    ) -> None:
        self.version = version
        self.path_configuration = path_configuration

    @staticmethod
    def from_dict(obj: Any) -> "PolicyCowConfig":
        assert isinstance(obj, dict)
        version = from_union([from_str, from_none], obj.get("version"))
        path_configuration = from_union(
            [PathConfiguration.from_dict, from_none], obj.get("pathConfiguration")
        )
        return PolicyCowConfig(version, path_configuration)

    def to_dict(self) -> dict:
        result: dict = {}
        result["version"] = from_union([from_str, from_none], self.version)
        result["pathConfiguration"] = from_union(
            [lambda x: to_class(PathConfiguration, x), from_none],
            self.path_configuration,
        )
        return result


class AdditionalInfos:
    policy_cow_config: Optional[PolicyCowConfig]
    path: Optional[str]
    rule_name: Optional[str]
    execution_id: Optional[str]
    rule_execution_id: Optional[str]
    task_execution_id: Optional[str]

    def __init__(
        self,
        policy_cow_config: Optional[PolicyCowConfig],
        path: Optional[str],
        rule_name: Optional[str],
        execution_id: Optional[str],
        rule_execution_id: Optional[str],
        task_execution_id: Optional[str],
    ) -> None:
        self.policy_cow_config = policy_cow_config
        self.path = path
        self.rule_name = rule_name
        self.execution_id = execution_id
        self.rule_execution_id = rule_execution_id
        self.task_execution_id = task_execution_id

    @staticmethod
    def from_dict(obj: Any) -> "AdditionalInfos":
        assert isinstance(obj, dict)
        policy_cow_config = from_union(
            [PolicyCowConfig.from_dict, from_none], obj.get("policyCowConfig")
        )
        path = from_union([from_str, from_none], obj.get("path"))
        rule_name = from_union([from_str, from_none], obj.get("ruleName"))
        execution_id = from_union([from_str, from_none], obj.get("executionID"))
        rule_execution_id = from_union(
            [from_str, from_none], obj.get("ruleExecutionID")
        )
        task_execution_id = from_union(
            [from_str, from_none], obj.get("taskExecutionID")
        )
        return AdditionalInfos(
            policy_cow_config,
            path,
            rule_name,
            execution_id,
            rule_execution_id,
            task_execution_id,
        )

    def to_dict(self) -> dict:
        result: dict = {}
        result["policyCowConfig"] = from_union(
            [lambda x: to_class(PolicyCowConfig, x), from_none], self.policy_cow_config
        )
        result["path"] = from_union([from_str, from_none], self.path)
        result["ruleName"] = from_union([from_str, from_none], self.rule_name)
        result["executionID"] = from_union([from_str, from_none], self.execution_id)
        result["ruleExecutionID"] = from_union(
            [from_str, from_none], self.rule_execution_id
        )
        result["taskExecutionID"] = from_union(
            [from_str, from_none], self.task_execution_id
        )
        return result


def additional_infos_from_dict(s: Any) -> AdditionalInfos:
    return AdditionalInfos.from_dict(s)


def additional_infos_to_dict(x: AdditionalInfos) -> Any:
    return to_class(AdditionalInfos, x)


class TaskInputs(SystemInputs):
    user_inputs: dict
    additional_infos: dict
    from_date: datetime
    to_date: datetime

    def __init__(
        self,
        user_inputs: dict,
        user_object: dict,
        system_objects: dict,
        meta_data: dict,
        additional_infos: dict,
        from_date: datetime,
        to_date: datetime,
    ) -> None:
        SystemInputs.__init__(self, user_object, system_objects, meta_data)
        self.user_inputs = user_inputs
        self.additional_infos = additional_infos
        self.from_date = from_date
        self.to_date = to_date

    @staticmethod
    def from_dict(obj: Any) -> "TaskInputs":
        (
            user_inputs,
            user_object,
            system_objects,
            meta_data,
            additional_info,
            from_date,
            to_date,
        ) = (None, None, None, None, None, None, None)
        if isinstance(obj, dict):
            if cowdictutils.is_valid_key(obj, "UserInputs"):
                user_inputs = obj.get("UserInputs")
            if cowdictutils.is_valid_key(obj, "userInputs"):
                user_inputs = obj.get("userInputs")
            if cowdictutils.is_valid_key(obj, "UserObject"):
                user_object = object_template_from_dict(obj.get("UserObject"))
            if cowdictutils.is_valid_key(obj, "userObject"):
                user_object = object_template_from_dict(obj.get("userObject"))
            if cowdictutils.is_valid_array(obj, "SystemObjects"):
                system_objects = from_list(
                    ObjectTemplate.from_dict, obj.get("SystemObjects")
                )
            if cowdictutils.is_valid_array(obj, "systemObjects"):
                system_objects = from_list(
                    ObjectTemplate.from_dict, obj.get("systemObjects")
                )
            if cowdictutils.is_valid_key(obj, "MetaData"):
                meta_data = meta_data_template_from_dict(obj.get("MetaData"))
            if cowdictutils.is_valid_key(obj, "metaData"):
                meta_data = meta_data_template_from_dict(obj.get("metaData"))
            if cowdictutils.is_valid_key(obj, "AdditionalInfos"):
                additional_info = additional_infos_from_dict(obj.get("AdditionalInfos"))

            from_date = obj.get("fromDate", None)
            if not from_date:
                from_date = obj.get("FromDate_", None)

            to_date = obj.get("toDate", None)
            if not to_date:
                to_date = obj.get("ToDate_", None)

            if from_date:
                from_date = parser.parse(from_date)

            if to_date:
                to_date = parser.parse(to_date)

        return TaskInputs(
            user_inputs,
            user_object,
            system_objects,
            meta_data,
            additional_info,
            from_date,
            to_date,
        )

    def to_dict(self) -> dict:
        result: dict = {}
        result["UserInputs"] = self.user_inputs
        result["fromDate"] = self.from_date.isoformat()
        result["toDate"] = self.to_date.isoformat()
        return result


def task_inputs_from_dict(s: Any) -> TaskInputs:
    return TaskInputs.from_dict(s)


def task_inputs_to_dict(x: TaskInputs) -> Any:
    return to_class(TaskInputs, x)


class CowException(Exception):
    def __init__(self, m):
        self.message = m

    def __str__(self):
        return self.message

import platform
from enum import Enum

from Utils.logger_utils import logger


class DistroType(Enum):
    DEB = "deb"
    RPM = "rpm"
    OTHER = "other"


def get_distro_type() -> DistroType:
    try:
        os_release = platform.freedesktop_os_release()
    except OSError:
        return DistroType.OTHER

    distro_id = os_release.get("ID", "").lower()
    id_like = os_release.get("ID_LIKE", "").lower()
    logger.log_info(f"Detected distro: ID={distro_id}, ID_LIKE={id_like}")

    debian_ids = {"debian", "ubuntu", "linuxmint", "pop", "elementary", "kali", "parrot"}
    rpm_ids = {"fedora", "rhel", "centos", "ol", "oraclelinux", "oracle", "rocky", "alma", "scientific", "opensuse", "sles", "suse"}

    if distro_id in debian_ids or "debian" in id_like:
        return DistroType.DEB
    if distro_id in rpm_ids or "fedora" in id_like or "rhel" in id_like:
        return DistroType.RPM

    return DistroType.OTHER


def is_fedora_35() -> bool:
    try:
        os_release = platform.freedesktop_os_release()
    except OSError:
        return False
    return os_release.get("ID", "").lower() == "fedora" and os_release.get("VERSION_ID", "") == "35"

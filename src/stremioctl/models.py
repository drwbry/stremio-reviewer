"""Lossless in-memory model of a Stremio add-on collection.

The descriptors are kept as their original parsed JSON objects. Nothing is
normalized, dropped, or reordered, so a parse/serialize round trip is byte-for
-byte faithful apart from insignificant whitespace. Typed accessors are
conveniences layered on top of that raw data.
"""

from __future__ import annotations

import copy
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from stremioctl.errors import ValidationError

KNOWN_DESCRIPTOR_KEYS = frozenset({"manifest", "transportUrl", "transportName", "flags"})


@dataclass(frozen=True)
class AddonDescriptor:
    """A single add-on descriptor, wrapping its raw parsed object."""

    data: dict[str, Any]

    @property
    def manifest(self) -> dict[str, Any] | None:
        value = self.data.get("manifest")
        return value if isinstance(value, dict) else None

    @property
    def manifest_id(self) -> str | None:
        manifest = self.manifest
        if manifest is None:
            return None
        value = manifest.get("id")
        return value if isinstance(value, str) and value.strip() else None

    @property
    def transport_url(self) -> str | None:
        value = self.data.get("transportUrl")
        return value if isinstance(value, str) else None

    @property
    def transport_name(self) -> str | None:
        value = self.data.get("transportName")
        return value if isinstance(value, str) else None

    @property
    def flags(self) -> dict[str, Any] | None:
        value = self.data.get("flags")
        return value if isinstance(value, dict) else None

    @property
    def unknown_descriptor_fields(self) -> list[str]:
        return sorted(key for key in self.data if key not in KNOWN_DESCRIPTOR_KEYS)

    def to_json(self) -> dict[str, Any]:
        """Return an independent deep copy of the raw descriptor object."""

        return copy.deepcopy(self.data)


@dataclass(frozen=True)
class AddonCollection:
    """An ordered collection of add-on descriptors."""

    descriptors: tuple[AddonDescriptor, ...]

    def __len__(self) -> int:
        return len(self.descriptors)

    def __iter__(self) -> Iterator[AddonDescriptor]:
        return iter(self.descriptors)

    def to_json(self) -> list[dict[str, Any]]:
        return [descriptor.to_json() for descriptor in self.descriptors]


def parse_collection(payload: Any) -> AddonCollection:
    """Wrap a parsed JSON payload as an :class:`AddonCollection`.

    Only structurally unusable input is rejected here (a non-array root, or a
    descriptor that is not a JSON object). Everything else - missing fields,
    duplicate ids, insecure transports - is the job of ``stremioctl.validation``.
    """

    if not isinstance(payload, list):
        raise ValidationError("Add-on collection root must be a JSON array")

    descriptors: list[AddonDescriptor] = []
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            raise ValidationError(f"Descriptor at index {index} must be a JSON object")
        descriptors.append(AddonDescriptor(data=item))
    return AddonCollection(descriptors=tuple(descriptors))


__all__ = ["KNOWN_DESCRIPTOR_KEYS", "AddonCollection", "AddonDescriptor", "parse_collection"]

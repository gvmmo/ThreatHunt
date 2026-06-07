from typing import Dict, List, Any
from dataclasses import dataclass

@dataclass
class RelationshipType:
    description: str
    accessibility: str
    return_type: str

class VTRelationships:
    # All available relationship types and their metadata
    RELATIONSHIPS: Dict[str, RelationshipType] = {
        "caa_records": RelationshipType(
            "Records CAA for the domain",
            "VT Enterprise",
            "List of Domains"
        ),
        "cname_records": RelationshipType(
            "Records CNAME for the domain",
            "VT Enterprise",
            "List of Domains"
        ),
        "comments": RelationshipType(
            "Community posted comments about the domain",
            "Everyone",
            "List of Comments"
        ),
        "communicating_files": RelationshipType(
            "Files that communicate with the domain",
            "Everyone",
            "List of Files"
        ),
        "downloaded_files": RelationshipType(
            "Files downloaded from that domain",
            "VT Enterprise",
            "List of Files"
        ),
        "graphs": RelationshipType(
            "Graphs including the domain",
            "Everyone",
            "List of Graphs"
        ),
        "historical_ssl_certificates": RelationshipType(
            "SSL certificates associated with the domain",
            "Everyone",
            "List of SSL Certificate"
        ),
        "historical_whois": RelationshipType(
            "WHOIS information for the domain",
            "Everyone",
            "List of Whois"
        ),
        "immediate_parent": RelationshipType(
            "Domain's immediate parent",
            "Everyone",
            "A single Domain"
        ),
        "mx_records": RelationshipType(
            "Records MX for the domain",
            "VT Enterprise",
            "List of Domains"
        ),
        "ns_records": RelationshipType(
            "Records NS for the domain",
            "VT Enterprise",
            "List of Domains"
        ),
        "parent": RelationshipType(
            "Domain's top parent",
            "Everyone",
            "A single Domain"
        ),
        "referrer_files": RelationshipType(
            "Files containing the domain",
            "Everyone",
            "List of Files"
        ),
        "related_comments": RelationshipType(
            "Community posted comments in the domain's related objects",
            "Everyone",
            "List of Comments"
        ),
        "related_references": RelationshipType(
            "References related to the domain",
            "VT Enterprise",
            "List of References"
        ),
        "related_threat_actors": RelationshipType(
            "Threat actors related to the domain",
            "VT Enterprise",
            "List of Threat Actors"
        ),
        "resolutions": RelationshipType(
            "DNS resolutions for the domain",
            "Everyone",
            "List of Resolutions"
        ),
        "soa_records": RelationshipType(
            "Records SOA for the domain",
            "VT Enterprise",
            "List of Domains"
        ),
        "siblings": RelationshipType(
            "Domain's sibling domains",
            "Everyone",
            "List of Domains"
        ),
        "subdomains": RelationshipType(
            "Domain's subdomains",
            "Everyone",
            "List of Domains"
        ),
        "urls": RelationshipType(
            "URLs having this domain",
            "VT Enterprise",
            "List of URLs"
        ),
        "user_votes": RelationshipType(
            "Current user's votes",
            "Everyone",
            "List of Votes"
        )
    }

    # Default relationships to query if none specified (free tier accessible ones)
    DEFAULT_RELATIONSHIPS = [
        "communicating_files",
        "referrer_files",
        "subdomains",
    ]

    @classmethod
    def get_free_relationships(cls) -> List[str]:
        """Returns list of relationships accessible to free tier users"""
        return [
            rel_type for rel_type, metadata in cls.RELATIONSHIPS.items()
            if metadata.accessibility == "Everyone"
        ]

    @classmethod
    def validate_relationships(cls, relationships = None) -> Dict[str, Any]:
        """
        Validates requested relationship types
        
        Args:
            relationships: List of relationship types to validate

        Returns:
            Dict containing validation results and any errors
        """
        if not relationships:
            return {
                "valid": True,
                "relationships": cls.DEFAULT_RELATIONSHIPS,
                "message": "Using default relationships"
            }

        invalid_types = [r for r in relationships if r not in cls.RELATIONSHIPS]
        enterprise_types = [
            r for r in relationships 
            if r in cls.RELATIONSHIPS and cls.RELATIONSHIPS[r].accessibility == "VT Enterprise"
        ]

        if invalid_types or enterprise_types:
            return {
                "valid": False,
                "invalid_types": invalid_types,
                "enterprise_only": enterprise_types,
                "available_types": cls.get_free_relationships(),
                "message": "Invalid or enterprise-only relationship types requested"
            }

        return {
            "valid": True,
            "relationships": relationships,
            "message": "All requested relationships are valid"
        }

# Make sure the class is available for import
__all__ = ['VTRelationships', 'RelationshipType']

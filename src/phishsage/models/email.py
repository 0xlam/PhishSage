from dataclasses import dataclass

@dataclass
class EmailHeaderContext:
    display_name: str
    from_address: str
    from_email: str
    from_domain: str
    to_email: list[str]
    cc_email: list[str]
    bcc_email: list[str]
    reply_to_address: str
    reply_to_email: str
    reply_to_domain: str
    return_path: str
    return_path_email: str
    return_path_domain: str
    message_id: str
    message_id_domain: str
    auth_results: str
    date: str
    subject: str
    received_chain: list[str]
    mail_id: str
    sender_ip: str


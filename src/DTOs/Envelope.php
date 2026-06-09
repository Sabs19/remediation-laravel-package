<?php

namespace Develler\RemediationAgent\DTOs;

final class Envelope
{
    public function __construct(
        public readonly string $protocolVersion,
        public readonly string $messageId,
        public readonly string $messageType,
        public readonly string $clientId,
        public readonly int    $issuedAt,
        public readonly string $nonce,
        public readonly string $hmacSha256,
        public readonly array  $payload,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            protocolVersion: (string) ($data['protocol_version'] ?? ''),
            messageId:       (string) ($data['message_id']       ?? ''),
            messageType:     (string) ($data['message_type']     ?? ''),
            clientId:        (string) ($data['client_id']        ?? ''),
            issuedAt:        (int)    ($data['issued_at']        ?? 0),
            nonce:           (string) ($data['nonce']            ?? ''),
            hmacSha256:      (string) ($data['hmac_sha256']      ?? ''),
            payload:         (array)  ($data['payload']          ?? []),
        );
    }

    public function majorVersion(): int
    {
        return (int) explode('.', $this->protocolVersion)[0];
    }
}

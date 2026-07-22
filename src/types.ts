export interface MirrorManifest {
  spec_version: '1.0';
  publisher: {
    name: string;
    canonical_origin: string;
  };
  issued_at: string;
  expires_at: string;
  sequence: number;
  mirrors: MirrorEntry[];
  revoked_mirrors: RevokedMirror[];
  keys: ManifestKey[];
  signatures: ManifestSignature[];
}

export interface MirrorEntry {
  id: string;
  url: string;
  type: 'https' | 'onion' | 'ipfs';
  status: 'active' | 'paused';
  priority: number;
  regions?: string[];
  content_scope?: string[];
  valid_from?: string;
  valid_until?: string;
}

export interface RevokedMirror {
  id: string;
  reason: string;
  revoked_at: string;
}

export interface ManifestKey {
  id: string;
  role: 'root' | 'targets' | 'emergency' | 'observer';
  algorithm: 'ed25519';
  public_key_pem: string;
}

export interface ManifestSignature {
  key_id: string;
  algorithm: 'ed25519';
  signature: string;
}

export type UnsignedManifest = Omit<MirrorManifest, 'signatures'> & {
  signatures?: ManifestSignature[];
};

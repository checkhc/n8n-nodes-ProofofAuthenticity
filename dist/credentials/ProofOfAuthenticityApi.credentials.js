"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ProofOfAuthenticityApi = void 0;
class ProofOfAuthenticityApi {
    constructor() {
        this.name = 'proofOfAuthenticityApi';
        this.displayName = 'ProofOfAuthenticity API';
        this.documentationUrl = 'https://docs.checkhc.net/';
        this.properties = [
            {
                displayName: 'DigiCryptoStore URL',
                name: 'digiCryptoStoreUrl',
                type: 'string',
                default: 'https://app2.photocertif.com',
                placeholder: 'https://app2.photocertif.com',
                description: 'The URL of your DigiCryptoStore instance (with HTTPS)',
                required: true,
            },
            {
                displayName: 'API Key (Bearer Token)',
                name: 'apiKey',
                type: 'string',
                typeOptions: {
                    password: true,
                },
                default: '',
                placeholder: 'your-api-key',
                description: 'API Key for authentication (found in Settings > API Keys)',
                required: true,
            },
        ];
        this.authenticate = {
            type: 'generic',
            properties: {
                headers: {
                    Authorization: '=Bearer {{$credentials.apiKey}}',
                },
            },
        };
        this.test = {
            request: {
                baseURL: '={{$credentials.digiCryptoStoreUrl}}',
                url: '/api/auth/me',
                method: 'GET',
            },
        };
    }
}
exports.ProofOfAuthenticityApi = ProofOfAuthenticityApi;

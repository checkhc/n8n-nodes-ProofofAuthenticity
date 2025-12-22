import {
	IAuthenticateGeneric,
	ICredentialTestRequest,
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

export class ProofOfAuthenticityApi implements ICredentialType {
	name = 'proofOfAuthenticityApi';
	displayName = 'ProofOfAuthenticity API';
	documentationUrl = 'https://docs.checkhc.net/';
	properties: INodeProperties[] = [
		{
			displayName: 'DigiCryptoStore URL',
			name: 'digiCryptoStoreUrl',
			type: 'string',
			default: 'https://localhost:3000',
			placeholder: 'https://your-instance.com or https://localhost:3000',
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

	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			headers: {
				Authorization: '=Bearer {{$credentials.apiKey}}',
			},
		},
	};

	test: ICredentialTestRequest = {
		request: {
			baseURL: '={{$credentials.digiCryptoStoreUrl}}',
			url: '/api/auth/me',
			method: 'GET',
		},
	};
}

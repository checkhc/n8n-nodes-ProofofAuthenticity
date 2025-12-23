import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeOperationError,
} from 'n8n-workflow';

import axios from 'axios';
import * as https from 'https';

// Security and Performance Constants
const REQUEST_TIMEOUT = 30000;          // 30 seconds for API requests
const DOWNLOAD_TIMEOUT = 120000;        // 2 minutes for file downloads
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB maximum file size

/**
 * Validates URL to prevent SSRF attacks
 * Only allows http/https protocols and blocks private IPs
 */
function validateUrl(url: string): void {
	const parsed = new URL(url);
	
	// Only allow http/https
	if (!['http:', 'https:'].includes(parsed.protocol)) {
		throw new Error(`Invalid URL protocol: ${parsed.protocol}. Only http/https allowed.`);
	}
	
	// Block private IPs and localhost (except for development)
	const hostname = parsed.hostname.toLowerCase();
	const privatePatterns = [
		/^10\./,
		/^172\.(1[6-9]|2[0-9]|3[0-1])\./,
		/^192\.168\./,
		/^127\./,
		/^0\./,
		/^169\.254\./,
	];
	
	for (const pattern of privatePatterns) {
		if (pattern.test(hostname)) {
			throw new Error(`URL points to private IP range: ${hostname}`);
		}
	}
	
	if (hostname === 'localhost' || hostname.endsWith('.local')) {
		throw new Error(`URL points to local hostname: ${hostname}`);
	}
}

/**
 * Creates axios config with HTTPS agent for self-signed certificates in local development
 */
function getAxiosConfig(baseUrl: string): { httpsAgent?: https.Agent } {
	if (baseUrl.includes('localhost') || baseUrl.includes('127.0.0.1')) {
		return {
			httpsAgent: new https.Agent({
				rejectUnauthorized: false
			})
		};
	}
	return {};
}

export class ProofOfAuthenticity implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'ProofOfAuthenticity by CHECKHC',
		name: 'proofOfAuthenticity',
		icon: 'file:proofofauthenticity.png',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description: 'ProofOfAuthenticity by CHECKHC - Blockchain timestamping with AI detection and C2PA authenticity. Learn more: https://www.checkhc.net',
		defaults: {
			name: 'ProofOfAuthenticity by CHECKHC',
		},
		inputs: ['main'],
		outputs: ['main'],
		credentials: [
			{
				name: 'proofOfAuthenticityApi',
				required: false,
				displayOptions: {
					show: {
						credentialType: ['proofOfAuthenticityApi'],
					},
				},
			},
			{
				name: 'digiCryptoStoreApi',
				required: false,
				displayOptions: {
					show: {
						credentialType: ['digiCryptoStoreApi'],
					},
				},
			},
		],
		properties: [
			// Credential Type Selection
			{
				displayName: 'Credential Type',
				name: 'credentialType',
				type: 'options',
				options: [
					{
						name: 'ProofOfAuthenticity API (Light)',
						value: 'proofOfAuthenticityApi',
						description: 'Use dedicated ProofOfAuthenticity credentials',
					},
					{
						name: 'DigiCryptoStore API (Shared)',
						value: 'digiCryptoStoreApi',
						description: 'Use existing DigiCryptoStore credentials (same API)',
					},
				],
				default: 'proofOfAuthenticityApi',
				description: 'Choose which credential to use. Both use the same CHECKHC API.',
			},
			// Operation
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Create Certificate',
						value: 'createCertificate',
						description: 'Create blockchain certificate with optional AI analysis and C2PA',
						action: 'Create certificate',
					},
					{
						name: 'List Certificates',
						value: 'listCertificates',
						description: 'List all your blockchain certificates',
						action: 'List certificates',
					},
				],
				default: 'createCertificate',
			},

			// ============================================
			// CERTIFICATION MODE SELECTOR
			// ============================================
			{
				displayName: 'Certification Mode',
				name: 'certificationMode',
				type: 'options',
				displayOptions: {
					show: {
						operation: ['createCertificate'],
					},
				},
				options: [
					{
						name: 'Blockchain Hash Only (1 credit)',
						value: 'simple',
						description: 'SHA-256 hash timestamped on Solana blockchain. File stays on your device.',
					},
					{
						name: 'Blockchain Hash + AI + C2PA (30 credits)',
						value: 'ai',
						description: 'Hash + AI authenticity analysis + C2PA content authenticity metadata',
					},
				],
				default: 'simple',
				required: true,
			},

			// ============================================
			// CREATE CERTIFICATE PARAMETERS
			// ============================================
			{
				displayName: 'Input Type',
				name: 'inputType',
				type: 'options',
				displayOptions: {
					show: {
						operation: ['createCertificate'],
					},
				},
				options: [
					{
						name: 'URL',
						value: 'url',
						description: 'Download file from URL',
					},
					{
						name: 'Base64 String',
						value: 'base64',
						description: 'File content as base64 encoded string',
					},
				],
				default: 'url',
				description: 'How to provide the file content',
			},
			{
				displayName: 'File URL',
				name: 'fileUrl',
				type: 'string',
				displayOptions: {
					show: {
						operation: ['createCertificate'],
						inputType: ['url'],
					},
				},
				default: '',
				required: true,
				placeholder: 'https://example.com/image.jpg',
				description: 'URL of the file to certify',
			},
			{
				displayName: 'File Data (Base64)',
				name: 'fileData',
				type: 'string',
				displayOptions: {
					show: {
						operation: ['createCertificate'],
						inputType: ['base64'],
					},
				},
				default: '',
				required: true,
				placeholder: 'data:image/jpeg;base64,/9j/4AAQ...',
				description: 'Base64 encoded file with data URI prefix',
			},
			{
				displayName: 'Title',
				name: 'title',
				type: 'string',
				displayOptions: {
					show: {
						operation: ['createCertificate'],
					},
				},
				default: '',
				required: true,
				description: 'Certificate title',
			},
			{
				displayName: 'Author',
				name: 'author',
				type: 'string',
				displayOptions: {
					show: {
						operation: ['createCertificate'],
					},
				},
				default: '',
				description: 'Author name',
			},
			{
				displayName: 'Description',
				name: 'description',
				type: 'string',
				displayOptions: {
					show: {
						operation: ['createCertificate'],
					},
				},
				default: '',
				description: 'Certificate description',
			},

			// ============================================
			// LIST CERTIFICATES PARAMETERS
			// ============================================
			{
				displayName: 'Filter by Hash',
				name: 'filterHash',
				type: 'string',
				displayOptions: {
					show: {
						operation: ['listCertificates'],
					},
				},
				default: '',
				placeholder: '2eb0a0766d04971078ca73e1b9d2281b70fc4ca2...',
				description: 'Filter certificates by hash (partial match)',
			},
			{
				displayName: 'Filter by Filename',
				name: 'filterFilename',
				type: 'string',
				displayOptions: {
					show: {
						operation: ['listCertificates'],
					},
				},
				default: '',
				placeholder: 'DSC02158.JPG',
				description: 'Filter certificates by filename (partial match)',
			},
			{
				displayName: 'Filter by Signature',
				name: 'filterSignature',
				type: 'string',
				displayOptions: {
					show: {
						operation: ['listCertificates'],
					},
				},
				default: '',
				placeholder: '4ZxL8...',
				description: 'Filter certificates by blockchain signature (partial match)',
			},
			{
				displayName: 'Limit',
				name: 'limit',
				type: 'number',
				displayOptions: {
					show: {
						operation: ['listCertificates'],
					},
				},
				default: 100,
				description: 'Maximum number of results to return',
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];

		for (let i = 0; i < items.length; i++) {
			try {
				const operation = this.getNodeParameter('operation', i) as string;
				const credentialType = this.getNodeParameter('credentialType', i, 'proofOfAuthenticityApi') as string;
				const credentials = await this.getCredentials(credentialType, i);
				const baseUrl = (credentials.digiCryptoStoreUrl as string).replace(/\/$/, '');
				const apiKey = credentials.apiKey as string;

				let responseData: any;

				// ============================================
				// CREATE CERTIFICATE OPERATION
				// ============================================
				if (operation === 'createCertificate') {
					const title = this.getNodeParameter('title', i) as string;
					const author = this.getNodeParameter('author', i, '') as string;
					const description = this.getNodeParameter('description', i, '') as string;
					const certificationMode = this.getNodeParameter('certificationMode', i, 'simple') as string;
					const inputType = this.getNodeParameter('inputType', i, 'base64') as string;
					
					// Map certification mode to API parameters
					const usageType = certificationMode === 'simple' ? 'simple' : 'ai';

					let fileData: string;

					if (inputType === 'url') {
						const fileUrl = this.getNodeParameter('fileUrl', i) as string;
						
						// Validate URL to prevent SSRF
						validateUrl(fileUrl);
						
						const fileResponse = await axios.get(fileUrl, {
							timeout: DOWNLOAD_TIMEOUT,
							responseType: 'arraybuffer',
							maxContentLength: MAX_FILE_SIZE,
							maxBodyLength: MAX_FILE_SIZE,
						});

						const contentType = fileResponse.headers['content-type'] || 'application/octet-stream';
						const base64Data = Buffer.from(fileResponse.data).toString('base64');
						fileData = `data:${contentType};base64,${base64Data}`;
					} else {
						fileData = this.getNodeParameter('fileData', i) as string;
					}

					const requestBody: any = {
						file_data: fileData,
						title,
						description,
						usage_type: usageType,
						payment_mode: 'credits', // Use subscription credits
					};

					// Add AI options if AI mode is enabled
					if (usageType === 'ai') {
						requestBody.ai_endpoint = 'art';
						requestBody.enable_c2pa = true; // C2PA auto-enabled with AI
					}

					const response = await axios.post(
						`${baseUrl}/api/solmemo/create`,
						requestBody,
						{
							timeout: usageType === 'ai' ? 60000 : REQUEST_TIMEOUT, // 60s if AI
							headers: {
								'Authorization': `Bearer ${apiKey}`,
								'Content-Type': 'application/json',
							},
							...getAxiosConfig(baseUrl),
						},
					);

					responseData = response.data;
				}

				// ============================================
				// LIST CERTIFICATES OPERATION
				// ============================================
				else if (operation === 'listCertificates') {
					// Get filter parameters
					const filterHash = this.getNodeParameter('filterHash', i, '') as string;
					const filterFilename = this.getNodeParameter('filterFilename', i, '') as string;
					const filterSignature = this.getNodeParameter('filterSignature', i, '') as string;
					const limit = this.getNodeParameter('limit', i, 100) as number;
					
					// Build query string
					const queryParams = new URLSearchParams();
					if (filterHash) queryParams.append('hash', filterHash);
					if (filterFilename) queryParams.append('filename', filterFilename);
					if (filterSignature) queryParams.append('signature', filterSignature);
					queryParams.append('limit', limit.toString());
					
					const queryString = queryParams.toString();
					const url = `${baseUrl}/api/solmemo/list${queryString ? '?' + queryString : ''}`;
					
					const response = await axios.get(
						url,
						{
							timeout: REQUEST_TIMEOUT,
							headers: {
								'Authorization': `Bearer ${apiKey}`,
							},
							...getAxiosConfig(baseUrl),
						},
					);

					responseData = response.data;
				}

				// Return data
				returnData.push({
					json: responseData,
					pairedItem: { item: i },
				});

			} catch (error: any) {
				if (this.continueOnFail()) {
					returnData.push({
						json: {
							error: error.message,
							details: error.response?.data || {},
						},
						pairedItem: { item: i },
					});
					continue;
				}
				throw new NodeOperationError(this.getNode(), error.message, { itemIndex: i });
			}
		}

		return [returnData];
	}
}

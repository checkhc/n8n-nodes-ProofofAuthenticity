"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ProofOfAuthenticity = void 0;
const n8n_workflow_1 = require("n8n-workflow");
const axios_1 = __importDefault(require("axios"));
const https = __importStar(require("https"));
// Security and Performance Constants
const REQUEST_TIMEOUT = 30000; // 30 seconds for API requests
const DOWNLOAD_TIMEOUT = 120000; // 2 minutes for file downloads
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB maximum file size
/**
 * Validates URL to prevent SSRF attacks
 * Only allows http/https protocols and blocks private IPs
 */
function validateUrl(url) {
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
function getAxiosConfig(baseUrl) {
    if (baseUrl.includes('localhost') || baseUrl.includes('127.0.0.1')) {
        return {
            httpsAgent: new https.Agent({
                rejectUnauthorized: false
            })
        };
    }
    return {};
}
class ProofOfAuthenticity {
    constructor() {
        this.description = {
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
                    required: true,
                },
            ],
            properties: [
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
    }
    async execute() {
        var _a;
        const items = this.getInputData();
        const returnData = [];
        for (let i = 0; i < items.length; i++) {
            try {
                const operation = this.getNodeParameter('operation', i);
                const credentials = await this.getCredentials('proofOfAuthenticityApi', i);
                const baseUrl = credentials.digiCryptoStoreUrl.replace(/\/$/, '');
                const apiKey = credentials.apiKey;
                let responseData;
                // ============================================
                // CREATE CERTIFICATE OPERATION
                // ============================================
                if (operation === 'createCertificate') {
                    const title = this.getNodeParameter('title', i);
                    const author = this.getNodeParameter('author', i, '');
                    const description = this.getNodeParameter('description', i, '');
                    const certificationMode = this.getNodeParameter('certificationMode', i, 'simple');
                    const inputType = this.getNodeParameter('inputType', i, 'base64');
                    // Map certification mode to API parameters
                    const usageType = certificationMode === 'simple' ? 'simple' : 'ai';
                    let fileData;
                    if (inputType === 'url') {
                        const fileUrl = this.getNodeParameter('fileUrl', i);
                        // Validate URL to prevent SSRF
                        validateUrl(fileUrl);
                        const fileResponse = await axios_1.default.get(fileUrl, {
                            timeout: DOWNLOAD_TIMEOUT,
                            responseType: 'arraybuffer',
                            maxContentLength: MAX_FILE_SIZE,
                            maxBodyLength: MAX_FILE_SIZE,
                        });
                        const contentType = fileResponse.headers['content-type'] || 'application/octet-stream';
                        const base64Data = Buffer.from(fileResponse.data).toString('base64');
                        fileData = `data:${contentType};base64,${base64Data}`;
                    }
                    else {
                        fileData = this.getNodeParameter('fileData', i);
                    }
                    const requestBody = {
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
                    const response = await axios_1.default.post(`${baseUrl}/api/solmemo/create`, requestBody, {
                        timeout: usageType === 'ai' ? 60000 : REQUEST_TIMEOUT, // 60s if AI
                        headers: {
                            'Authorization': `Bearer ${apiKey}`,
                            'Content-Type': 'application/json',
                        },
                        ...getAxiosConfig(baseUrl),
                    });
                    responseData = response.data;
                }
                // ============================================
                // LIST CERTIFICATES OPERATION
                // ============================================
                else if (operation === 'listCertificates') {
                    // Get filter parameters
                    const filterHash = this.getNodeParameter('filterHash', i, '');
                    const filterFilename = this.getNodeParameter('filterFilename', i, '');
                    const filterSignature = this.getNodeParameter('filterSignature', i, '');
                    const limit = this.getNodeParameter('limit', i, 100);
                    // Build query string
                    const queryParams = new URLSearchParams();
                    if (filterHash)
                        queryParams.append('hash', filterHash);
                    if (filterFilename)
                        queryParams.append('filename', filterFilename);
                    if (filterSignature)
                        queryParams.append('signature', filterSignature);
                    queryParams.append('limit', limit.toString());
                    const queryString = queryParams.toString();
                    const url = `${baseUrl}/api/solmemo/list${queryString ? '?' + queryString : ''}`;
                    const response = await axios_1.default.get(url, {
                        timeout: REQUEST_TIMEOUT,
                        headers: {
                            'Authorization': `Bearer ${apiKey}`,
                        },
                        ...getAxiosConfig(baseUrl),
                    });
                    responseData = response.data;
                }
                // Return data
                returnData.push({
                    json: responseData,
                    pairedItem: { item: i },
                });
            }
            catch (error) {
                if (this.continueOnFail()) {
                    returnData.push({
                        json: {
                            error: error.message,
                            details: ((_a = error.response) === null || _a === void 0 ? void 0 : _a.data) || {},
                        },
                        pairedItem: { item: i },
                    });
                    continue;
                }
                throw new n8n_workflow_1.NodeOperationError(this.getNode(), error.message, { itemIndex: i });
            }
        }
        return [returnData];
    }
}
exports.ProofOfAuthenticity = ProofOfAuthenticity;

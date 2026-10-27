/**
 * Legacy API Client Re-export Adapter
 * Bridges imports pointing to frontend/src/api/client to the unified frontend/src/utils/api module.
 */

export * from '../utils/api';
export { apiClient as default } from '../utils/api';

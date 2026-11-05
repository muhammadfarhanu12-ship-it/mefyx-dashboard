import { useEffect, useState } from 'react';
import { useStore } from '../stores/useStore';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { Modal } from '../components/ui/Modal';
import { Plus, Copy, Check, Trash2, Eye, EyeOff, AlertTriangle, Info } from 'lucide-react';
import { motion } from 'framer-motion';
import { safeFormatDateWithPattern } from '../lib/date';
import type { ApiKey } from '../types';
import {
  FULL_KEY_UNAVAILABLE_MESSAGE,
  copyTextToClipboard,
  describeApiKeyError,
  type ApiKeyErrorInfo,
} from '../lib/apiKeys';

const MASKED_API_KEY = `sentinel_sk_${'*'.repeat(24)}`;

export default function ApiKeys() {
  const { apiKeys, fetchApiKeys, generateApiKey, revokeApiKey, isLoading } = useStore();
  const [showKey, setShowKey] = useState<Record<string, boolean>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [keyToRevoke, setKeyToRevoke] = useState<string | null>(null);
  const [error, setError] = useState<ApiKeyErrorInfo | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [newKey, setNewKey] = useState<ApiKey | null>(null);
  const [newKeyVisible, setNewKeyVisible] = useState(true);
  const [newKeyCopy, setNewKeyCopy] = useState<'idle' | 'copied' | 'failed'>('idle');

  useEffect(() => {
    fetchApiKeys();
  }, [fetchApiKeys]);

  const activeCount = apiKeys.filter((k) => k.status !== 'revoked').length;

  const handleCopy = async (key: string | undefined, id: string) => {
    setError(null);
    if (!key) {
      // Older keys: the full value is not recoverable. Explain instead of doing nothing.
      setNotice(FULL_KEY_UNAVAILABLE_MESSAGE);
      return;
    }
    setNotice(null);
    const ok = await copyTextToClipboard(key);
    if (ok) {
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    } else {
      setNotice('Your browser blocked copying. Show the key, select it, and press Ctrl+C (Cmd+C on Mac).');
    }
  };

  const toggleShowKey = (apiKey: ApiKey) => {
    setError(null);
    if (!apiKey.key) {
      setNotice(FULL_KEY_UNAVAILABLE_MESSAGE);
      return;
    }
    setNotice(null);
    setShowKey((prev) => ({ ...prev, [apiKey.id]: !prev[apiKey.id] }));
  };

  const handleGenerate = async () => {
    setError(null);
    setNotice(null);
    setIsGenerating(true);
    try {
      const created = await generateApiKey(`New Key ${apiKeys.length + 1}`);
      setNewKeyVisible(true);
      setNewKeyCopy('idle');
      setNewKey(created);
    } catch (err) {
      setError(describeApiKeyError(err));
    } finally {
      setIsGenerating(false);
    }
  };

  const handleCopyNewKey = async () => {
    const ok = await copyTextToClipboard(newKey?.key || '');
    setNewKeyCopy(ok ? 'copied' : 'failed');
    if (ok) setTimeout(() => setNewKeyCopy('idle'), 2500);
  };

  // Closing the dialog drops the one-time secret from memory by reloading the list from the server.
  const closeNewKeyDialog = () => {
    setNewKey(null);
    setNewKeyCopy('idle');
    void fetchApiKeys();
  };

  const confirmRevoke = async () => {
    if (keyToRevoke) {
      await revokeApiKey(keyToRevoke);
      setKeyToRevoke(null);
      setError(null);
    }
  };

  if (isLoading && apiKeys.length === 0) {
    return (
      <div className="space-y-6 animate-pulse">
        <div className="h-8 w-48 bg-slate-800 rounded"></div>
        <div className="h-64 bg-slate-800 rounded-xl"></div>
      </div>
    );
  }

  return (
    <motion.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="space-y-8"
    >
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <h1 className="text-3xl font-bold tracking-tight">API Keys</h1>
          <p className="text-slate-400 mt-1">Manage your gateway access keys and monitor usage.</p>
        </div>
        <Button onClick={handleGenerate} disabled={isGenerating} className="w-full sm:w-auto">
          <Plus className="w-4 h-4 mr-2" />
          {isGenerating ? 'Generating...' : 'Generate New Key'}
        </Button>
      </div>

      {error && (
        <div role="alert" className="flex items-start gap-3 rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-200">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-red-400" />
          <div className="flex-1">
            <p className="font-medium text-red-300">Could not generate an API key</p>
            <p className="mt-1 text-red-200/90">{error.message}</p>
          </div>
          <button type="button" onClick={() => setError(null)} className="text-red-300 hover:text-red-100" aria-label="Dismiss error">
            ×
          </button>
        </div>
      )}

      {notice && (
        <div role="status" className="flex items-start gap-3 rounded-lg border border-amber-500/30 bg-amber-500/10 p-4 text-sm text-amber-100">
          <Info className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" />
          <p className="flex-1">{notice}</p>
          <button type="button" onClick={() => setNotice(null)} className="text-amber-300 hover:text-amber-100" aria-label="Dismiss message">
            ×
          </button>
        </div>
      )}

      <Card className="bg-slate-900/40 border-white/5">
        <CardHeader>
          <CardTitle>Active Keys</CardTitle>
          <CardDescription>
            Use these keys to authenticate your requests to the Mefyx Gateway. {activeCount} active {activeCount === 1 ? 'key' : 'keys'}.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {apiKeys.map((apiKey) => (
              <div key={apiKey.id} className={`p-4 rounded-lg border ${apiKey.status === 'revoked' ? 'border-red-900/30 bg-red-900/10 opacity-60' : 'border-white/10 bg-slate-950/50'} flex min-w-0 flex-col justify-between gap-4 transition-all md:flex-row md:items-center`}>
                <div className="min-w-0 flex-1 space-y-1">
                  <div className="flex min-w-0 flex-wrap items-center gap-2">
                    <span className="font-medium text-slate-200">{apiKey.name}</span>
                    {apiKey.status === 'revoked' ? (
                      <Badge variant="destructive" className="bg-red-900/50 text-red-400 border-red-800/50">Revoked</Badge>
                    ) : (
                      <Badge variant="clean">Active</Badge>
                    )}
                  </div>
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-slate-400">
                    <span>Created {safeFormatDateWithPattern(apiKey.created_at, 'MMM d, yyyy')}</span>
                    <span>•</span>
                    <span>Last used {apiKey.last_used ? safeFormatDateWithPattern(apiKey.last_used, 'MMM d, yyyy') : 'Never'}</span>
                  </div>
                </div>

                <div className="flex min-w-0 flex-1 items-center space-x-2">
                  <div className="relative min-w-0 flex-1">
                    <div className="bg-[#0d1117] border border-white/10 rounded-md px-3 py-2 font-mono text-sm text-slate-300 flex items-center justify-between">
                      <span className="truncate mr-2">
                        {apiKey.key
                          ? (showKey[apiKey.id] || apiKey.status === 'revoked' ? apiKey.key : MASKED_API_KEY)
                          : MASKED_API_KEY}
                      </span>
                      <div className="flex items-center space-x-1 shrink-0">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-6 w-6 text-slate-400 hover:text-slate-200"
                          onClick={() => toggleShowKey(apiKey)}
                          disabled={apiKey.status === 'revoked'}
                          title={apiKey.key ? (showKey[apiKey.id] ? 'Hide key' : 'Show key') : 'Why can I not see this key?'}
                          aria-label={apiKey.key ? (showKey[apiKey.id] ? 'Hide key' : 'Show key') : 'Why can I not see this key?'}
                        >
                          {showKey[apiKey.id] ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-6 w-6 text-slate-400 hover:text-slate-200"
                          onClick={() => handleCopy(apiKey.key, apiKey.id)}
                          disabled={apiKey.status === 'revoked'}
                          title={apiKey.key ? 'Copy key' : 'Why can I not copy this key?'}
                          aria-label={apiKey.key ? 'Copy key' : 'Why can I not copy this key?'}
                        >
                          {copiedId === apiKey.id ? <Check className="h-3.5 w-3.5 text-clean" /> : <Copy className="h-3.5 w-3.5" />}
                        </Button>
                      </div>
                    </div>
                    {!apiKey.key && (
                      <div className="text-[11px] text-slate-400 mt-1">
                        Key value is only shown once when created. Lost it? Revoke this key and generate a new one.
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex w-full items-center justify-between gap-4 md:w-auto md:justify-end md:space-x-6">
                  <div className="text-sm">
                    <p className="text-slate-400">Requests</p>
                    <p className="font-medium text-slate-200">{apiKey.usage_count.toLocaleString()}</p>
                  </div>
                  {apiKey.status !== 'revoked' && (
                    <Button variant="destructive" size="sm" onClick={() => setKeyToRevoke(apiKey.id)}>
                      <Trash2 className="w-4 h-4 mr-2" />
                      Revoke
                    </Button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
      
      <div className="rounded-lg border border-indigo-500/20 bg-indigo-500/5 p-4 flex items-start space-x-3">
        <AlertTriangle className="w-5 h-5 text-indigo-400 mt-0.5 shrink-0" />
        <div className="text-sm text-indigo-200/80">
          <p className="font-medium text-indigo-300 mb-1">Security Best Practices</p>
          <p>Rotate your API keys every 90 days. Never commit keys to version control. Use environment variables to store them securely in your application.</p>
        </div>
      </div>

      <Modal
        isOpen={!!newKey}
        onClose={closeNewKeyDialog}
        title="Your new API key"
        description="Copy this key now and store it somewhere safe. For your security it will not be shown again."
      >
        <div className="space-y-4">
          <div className="flex items-center gap-2 rounded-md border border-white/10 bg-[#0d1117] px-3 py-2 font-mono text-sm text-slate-200">
            <span className="min-w-0 flex-1 select-all break-all" data-testid="new-api-key">
              {newKey?.key ? (newKeyVisible ? newKey.key : '•'.repeat(Math.min(newKey.key.length, 40))) : ''}
            </span>
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7 shrink-0 text-slate-400 hover:text-slate-200"
              onClick={() => setNewKeyVisible((v) => !v)}
              title={newKeyVisible ? 'Hide key' : 'Show key'}
              aria-label={newKeyVisible ? 'Hide key' : 'Show key'}
            >
              {newKeyVisible ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </Button>
          </div>
          <div aria-live="polite" className="min-h-5 text-sm">
            {newKeyCopy === 'copied' && <span className="text-emerald-400">Copied to clipboard.</span>}
            {newKeyCopy === 'failed' && (
              <span className="text-amber-300">Copy was blocked by your browser. Select the key above and press Ctrl+C (Cmd+C on Mac).</span>
            )}
          </div>
          <div className="flex flex-col-reverse gap-3 sm:flex-row sm:justify-end">
            <Button variant="outline" onClick={handleCopyNewKey}>
              {newKeyCopy === 'copied' ? <Check className="mr-2 h-4 w-4" /> : <Copy className="mr-2 h-4 w-4" />}
              {newKeyCopy === 'copied' ? 'Copied' : 'Copy key'}
            </Button>
            <Button onClick={closeNewKeyDialog}>I have saved my key</Button>
          </div>
        </div>
      </Modal>

      <Modal
        isOpen={!!keyToRevoke}
        onClose={() => setKeyToRevoke(null)}
        title="Revoke API Key"
        description="Are you sure you want to revoke this API key? Any applications using this key will immediately lose access to the Mefyx Gateway."
      >
        <div className="mt-6 flex flex-col-reverse gap-3 sm:flex-row sm:justify-end">
          <Button variant="outline" onClick={() => setKeyToRevoke(null)}>Cancel</Button>
          <Button variant="destructive" onClick={confirmRevoke}>Yes, Revoke Key</Button>
        </div>
      </Modal>
    </motion.div>
  );
}
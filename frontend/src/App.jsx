import React, { useEffect, useState } from 'react';

const API = 'http://127.0.0.1:8000';
export default function App() {
  const [token, setToken] = useState(localStorage.getItem('tv_token') || '');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [documents, setDocuments] = useState([]);
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState('');
  const [message, setMessage] = useState('');
  const [file, setFile] = useState(null);

  async function request(path, options = {}) {
    const headers = { ...(options.headers || {}) };
    if (token) headers.Authorization = `Bearer ${token}`;
    const response = await fetch(`${API}${path}`, { ...options, headers });
    if (!response.ok) {
      let detail = `Request failed (${response.status})`;
      try { detail = (await response.json()).detail || detail; } catch {}
      throw new Error(detail);
    }
    if (response.status === 204) return null;
    const type = response.headers.get('content-type') || '';
    return type.includes('application/json') ? response.json() : response.blob();
  }

  async function login(event) {
    event.preventDefault();
    try {
      const result = await request('/auth/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      setToken(result.access_token);
      localStorage.setItem('tv_token', result.access_token);
      setMessage(`Signed in as ${result.role}.`);
    } catch (error) { setMessage(error.message); }
  }

  async function register() {
    try {
      await request('/auth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }) });
      setMessage('Account created as viewer. Sign in to continue.');
    } catch (error) { setMessage(error.message); }
  }

  async function loadDocuments() {
    try {
      const params = new URLSearchParams();
      if (query) params.set('q', query);
      if (category) params.set('category', category);
      setDocuments(await request(`/documents?${params.toString()}`));
    } catch (error) { setMessage(error.message); }
  }

  async function upload(event) {
    event.preventDefault();
    if (!file) { setMessage('Choose a file first.'); return; }
    const body = new FormData();
    body.append('file', file);
    body.append('category', category || 'General');
    try {
      await request('/documents', { method: 'POST', body });
      setMessage('Document uploaded.');
      setFile(null);
      await loadDocuments();
    } catch (error) { setMessage(error.message); }
  }

  async function download(doc) {
    try {
      const blob = await request(`/documents/${doc.id}/download`);
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url; link.download = doc.original_filename; link.click();
      URL.revokeObjectURL(url);
    } catch (error) { setMessage(error.message); }
  }

  async function deleteDoc(doc) {
    if (!window.confirm(`Delete "${doc.title}"?`)) return;
    try {
      await request(`/documents/${doc.id}`, { method: 'DELETE' });
      setMessage('Document deleted.');
      await loadDocuments();
    } catch (error) { setMessage(error.message); }
  }

  function logout() {
    setToken(''); localStorage.removeItem('tv_token'); setDocuments([]); setMessage('Signed out.');
  }

  useEffect(() => { if (token) loadDocuments(); }, [token]);

  return <main className="container">
    <header><div><p className="eyebrow">SECURE DOCUMENT SHARING</p><h1>TrustVault</h1>
      <p className="subtitle">Private documents. Explicit permissions. Auditable activity.</p></div>
      {token && <button className="secondary" onClick={logout}>Sign out</button>}
    </header>
    {message && <div className="message" role="status">{message}</div>}
    {!token ? <section className="panel">
      <h2>Sign in</h2>
      <form onSubmit={login} className="stack">
        <label>Email<input type="email" value={email} onChange={e => setEmail(e.target.value)} required /></label>
        <label>Password<input type="password" value={password} onChange={e => setPassword(e.target.value)} minLength="10" required /></label>
        <div className="actions"><button type="submit">Sign in</button><button type="button" className="secondary" onClick={register}>Create viewer account</button></div>
      </form>
      <p className="hint">New registrations receive the viewer role. Owner/admin provisioning should be done by a trusted administrator.</p>
    </section> : <>
      <section className="panel">
        <h2>Upload a document</h2>
        <form onSubmit={upload} className="upload-row">
          <input type="file" accept=".pdf,.png,.jpg,.jpeg,.txt" onChange={e => setFile(e.target.files?.[0] || null)} required />
          <input aria-label="Category" placeholder="Category (e.g. Finance)" value={category} onChange={e => setCategory(e.target.value)} maxLength="80" />
          <button type="submit">Upload</button>
        </form>
        <p className="hint">Allowed: PDF, PNG, JPG, TXT. The API validates file size and content signature.</p>
      </section>
      <section className="panel">
        <div className="section-heading"><h2>Your shared documents</h2><button className="secondary" onClick={loadDocuments}>Refresh</button></div>
        <div className="search-row">
          <input placeholder="Search document name" value={query} onChange={e => setQuery(e.target.value)} />
          <input placeholder="Filter category" value={category} onChange={e => setCategory(e.target.value)} />
          <button onClick={loadDocuments}>Search</button>
        </div>
        {documents.length === 0 ? <p className="empty">No documents available. Upload a file or ask an owner to grant access.</p> :
          <div className="table-wrap"><table><thead><tr><th>Document</th><th>Category</th><th>Access</th><th>Size</th><th>Actions</th></tr></thead>
            <tbody>{documents.map(doc => <tr key={doc.id}><td><strong>{doc.title}</strong><small>{doc.original_filename}</small></td>
              <td>{doc.category}</td><td><span className="tag">{doc.permission}</span></td>
              <td>{Math.max(1, Math.round(doc.size_bytes / 1024))} KB</td>
              <td className="actions"><button onClick={() => download(doc)}>Download</button>
                {(doc.permission === 'owner') && <button className="danger" onClick={() => deleteDoc(doc)}>Delete</button>}</td>
            </tr>)}</tbody></table></div>}
      </section>
      <p className="security-note">Security note: the server checks document permissions on every request. This UI is not the security boundary.</p>
    </>}
    <footer>TrustVault • Educational security project</footer>
  </main>;
}

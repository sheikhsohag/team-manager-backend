'use strict';

// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  // Multer (file upload) errors: report as 400 with a friendly message.
  if (err && err.name === 'MulterError') {
    const msg = err.code === 'LIMIT_FILE_SIZE' ? 'File too large (max 20 MB)' : err.message;
    return res.status(400).json({ error: msg, code: err.code });
  }
  const status = err.status || 500;
  if (status >= 500) {
    console.error('[error]', err);
  }
  res.status(status).json({
    error: err.publicMessage || err.message || 'Internal Server Error',
    ...(err.details ? { details: err.details } : {}),
  });
}

function notFound(req, res) {
  res.status(404).json({ error: 'Not found' });
}

/** Wrap an async controller so thrown errors reach the error handler. */
function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

module.exports = { errorHandler, notFound, asyncHandler };

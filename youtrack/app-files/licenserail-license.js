// LicenseRail admin endpoints for the License page (widget "licenserail-license"). Administrators only; responses never
// contain the license key or the token (Marketplace rule: open endpoints don't expose license data).

const licenserail = require('./licenserail');

function isAdmin(ctx) {
  try { return ctx.currentUser.hasPermission('ADMIN_UPDATE_APP'); } catch (e) { return false; }
}

function guard(ctx, run) {
  if (!isAdmin(ctx)) {
    ctx.response.statusCode = 403;
    ctx.response.json({ error: 'forbidden', message: 'Only administrators can manage the license.' });
    return;
  }
  try {
    run();
  } catch (e) {
    ctx.response.statusCode = 400;
    ctx.response.json({ error: 'bad_request', message: e && e.message ? e.message : String(e) });
  }
}

function body(ctx) {
  try { return ctx.request.json() || {}; } catch (e) { return {}; }
}

function remember(ctx) {
  const id = body(ctx).installationId;
  if (id) licenserail.setInstallation(ctx, id);
}

exports.httpHandler = {
  endpoints: [
    {
      method: 'GET',
      path: 'status',
      permissions: ['ADMIN_UPDATE_APP'],
      handle: function (ctx) {
        guard(ctx, function () { ctx.response.json(licenserail.status(ctx)); });
      },
    },
    {
      method: 'POST',
      path: 'activate',
      permissions: ['ADMIN_UPDATE_APP'],
      handle: function (ctx) {
        guard(ctx, function () {
          remember(ctx);
          licenserail.activate(ctx);
          ctx.response.statusCode = 202;
          ctx.response.json(licenserail.status(ctx));
        });
      },
    },
    {
      method: 'POST',
      path: 'trial',
      permissions: ['ADMIN_UPDATE_APP'],
      handle: function (ctx) {
        guard(ctx, function () {
          remember(ctx);
          licenserail.startTrial(ctx, body(ctx).baseUrls);
          ctx.response.statusCode = 202;
          ctx.response.json(licenserail.status(ctx));
        });
      },
    },
    {
      method: 'POST',
      path: 'refresh',
      permissions: ['ADMIN_UPDATE_APP'],
      handle: function (ctx) {
        guard(ctx, function () {
          remember(ctx);
          licenserail.refresh(ctx);
          ctx.response.statusCode = 202;
          ctx.response.json(licenserail.status(ctx));
        });
      },
    },
    {
      method: 'POST',
      path: 'deactivate',
      permissions: ['ADMIN_UPDATE_APP'],
      handle: function (ctx) {
        guard(ctx, function () {
          licenserail.deactivate(ctx);
          ctx.response.statusCode = 202;
          ctx.response.json(licenserail.status(ctx));
        });
      },
    },
  ],
  asyncFunctions: licenserail.asyncFunctions,
};

// An app feature that needs a license (or a running trial).
const licenserail = require('./licenserail');

exports.httpHandler = {
  endpoints: [
    {
      method: 'GET',
      path: 'summary',
      handle: function (ctx) {
        const license = licenserail.check(ctx);
        if (!license.valid) {
          ctx.response.statusCode = 402;
          ctx.response.json({ error: 'license_required', status: license.status });
          return;
        }
        ctx.response.json({
          message: 'Licensed feature',
          trial: license.summary.isTrial,
          advanced: licenserail.hasFeature(ctx, 'advanced-reports'),
        });
      },
    },
  ],
  // Lets check() schedule the daily license refresh from this handler.
  asyncFunctions: licenserail.asyncFunctions,
};

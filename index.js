const OAuth2Strategy = require("passport-oauth2").Strategy;
const User = require("@saltcorn/data/models/user");
const Workflow = require("@saltcorn/data/models/workflow");
const Form = require("@saltcorn/data/models/form");

const { getState } = require("@saltcorn/data/db/state");

const authentication = (config) => {
  const cfg_base_url = getState().getConfig("base_url");
  const params = {
    clientID: config.clientID || "nokey",
    clientSecret: config.clientSecret || "nosecret",
    callbackURL: `${addSlash(cfg_base_url)}auth/callback/oauth2`,
    authorizationURL: config.authorizationURL || "noauthurl",
    tokenURL: config.tokenURL || "notokenurl",
  };
  return {
    oauth2: {
      label: config.label,
      parameters: config.scope ? { scope: [config.scope] } : {},
      strategy: new OAuth2Strategy(
        params,

        function (token, tokenSecret, profile, cb) {
          //console.log(profile);
          let email = "";
          if (profile._json && profile._json.email) email = profile._json.email;
          else if (profile.emails && profile.emails.length)
            email = profile.emails[0].value;
          User.findOrCreateByAttribute(
            "oauth2Id",
            profile[config.id_key || "id"],
            {
              email,
            }
          ).then((u) => {
            return cb(null, u.session_object);
          });
        }
      ),
    },
  };
};
const addSlash = (s) => (s[s.length - 1] === "/" ? s : s + "/");
const configuration_workflow = () => {
  const cfg_base_url = getState().getConfig("base_url"),
    base_url = addSlash(cfg_base_url || "http://base_url");
  const blurb = [
    !cfg_base_url
      ? "You should set the 'Base URL' configration property. "
      : "",
    `Create a new application. You should obtain the API key and secret,
 and set the callback URL to ${base_url}auth/callback/oauth2`,
  ];
  return new Workflow({
    steps: [
      {
        name: "API keys",
        form: () =>
          new Form({
            labelCols: 3,
            blurb,
            fields: [
              {
                name: "clientID",
                label: "Client ID",
                type: "String",
                required: true,
              },
              {
                name: "clientSecret",
                label: "Client Secret",
                type: "String",
                required: true,
              },
              {
                name: "label",
                label: "Label",
                sublabel: "How this login option will be described to the user",
                type: "String",
                required: true,
              },
              {
                name: "authorizationURL",
                label: "Authorization URL",
                type: "String",
                required: true,
              },
              {
                name: "tokenURL",
                label: "Token URL",
                type: "String",
                required: true,
              },
              {
                name: "scope",
                label: "Scope",
                type: "String",
              },
              {
                name: "id_key",
                label: "ID Key",
                type: "String",
                sublabel:
                  "A key in the profile object to a unique user identifier",
                default: "id",
              },
            ],
          }),
      },
    ],
  });
};
module.exports = {
  sc_plugin_api_version: 1,
  authentication,
  configuration_workflow,
};

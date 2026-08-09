require "yaml"
require "json"

class ImportsController < ApplicationController
  def yaml_load
    imported = YAML.unsafe_load(params[:payload].to_s) # VULN YAML-001: unsafe YAML import instantiates attacker-controlled Ruby objects
    rendered = imported.respond_to?(:result) ? imported.result(binding) : imported.inspect
    render plain: rendered
  end

  def json_import
    parsed = JSON.parse(params[:payload].to_s)
    render json: { ok: true, keys: parsed.keys }
  rescue JSON::ParserError
    render json: { error: "invalid json" }, status: :bad_request
  end
end

require "yaml"
require "json"

class ImportsController < ApplicationController
  def yaml_load
    imported = YAML.safe_load(params[:payload].to_s, permitted_classes: [Hash, Array, String, Integer, Float, TrueClass, FalseClass, NilClass], aliases: false) # SAFE YAML-001: safe_load only permits primitive import data
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

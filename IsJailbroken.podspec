Pod::Spec.new do |s|
  s.name              = "isJailbroken"
  s.version           = "1.0"
  s.summary           = "Jailbreak detection"
  s.description       = "Jailbreak detection"
  s.homepage          = "https://github.com/aschuch/QRCode"
  s.license           = { :type => "GPLv3", :file => "LICENSE" }
  s.author            = { "fork" => "fork@fork" }
  s.platform          = :ios, "9.0"
  s.source            = { :git => "https://github.com/alexmay23/isJailbroken", :tag => s.version }
  s.requires_arc      = true
  s.source_files      = "isJailbroken/JB.m", "isJailbroken/JB.h"
  s.public_header_files = "isJailbroken/JB.h"
end

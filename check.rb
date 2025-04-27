require 'resolv'
require 'json'
require 'timeout'

def safe_dns_lookup(seconds = 5)
  Timeout.timeout(seconds) { yield }
rescue Timeout::Error
  []
end

def likely_using_m365?(domain)
  # Check MX Records
  mx_records = safe_dns_lookup { Resolv::DNS.open { |dns| dns.getresources(domain, Resolv::DNS::Resource::IN::MX) } }
  mx_points_to_m365 = mx_records.any? { |mx| mx.exchange.to_s.include?('protection.outlook.com') }

  # Check Autodiscover CNAME
  autodiscover_record = safe_dns_lookup { Resolv::DNS.open { |dns| dns.getresources("autodiscover.#{domain}", Resolv::DNS::Resource::IN::CNAME) } }
  autodiscover_points_to_m365 = autodiscover_record.any? { |cname| cname.name.to_s.include?('autodiscover.outlook.com') }

  # Check TXT Records (SPF)
  txt_records = safe_dns_lookup { Resolv::DNS.open { |dns| dns.getresources(domain, Resolv::DNS::Resource::IN::TXT) } }
  spf_points_to_m365 = txt_records.any? { |txt| txt.strings.join.include?('spf.protection.outlook.com') }

  # Determine if domain is likely using M365
  mx_points_to_m365 || autodiscover_points_to_m365 || spf_points_to_m365
end

input = {
  "emails" => [
    "foi@abertay.ac.uk",
    "infocompliance@aber.ac.uk",
    "foi@anglia.ac.uk",
    "foi_requests@aston.ac.uk",
    "info-compliance@bangor.ac.uk",
    "foi-officer@bathspa.ac.uk",
    "foi@bbk.ac.uk",
    "FreedomOfInformation@bcu.ac.uk",
    "FOIA@bournemouth.ac.uk",
    "foirequests@brunel.ac.uk",
    "FOIofficer@bucks.ac.uk",
    "foi@canterbury.ac.uk",
    "freedomofinfo@cardiffmet.ac.uk",
    "Inforequest@cardiff.ac.uk",
    "foi@cssd.ac.uk",
    "FOI@city.ac.uk",
    "foia@coventry.ac.uk",
    "foi@cranfield.ac.uk",
    "foi@dmu.ac.uk",
    "info.access@durham.ac.uk",
    "foi@edgehill.ac.uk",
    "foi@napier.ac.uk",
    "foi@gcu.ac.uk",
    "foi@glyndwr.ac.uk",
    "foi@gold.ac.uk",
    "katie.hudson@gsmd.ac.uk",
    "foi@harper-adams.ac.uk",
    "foi@hw.ac.uk",
    "s.rospigliosi@heythrop.ac.uk",
    "foi@imperial.ac.uk",
    "foi@ucl.ac.uk",
    "foi@keele.ac.uk",
    "info-compliance@kcl.ac.uk",
    "freedomofinformation@kingston.ac.uk",
    "foi@lancs.ac.uk",
    "foi@leedsbeckett.ac.uk",
    "foi@hope.ac.uk",
    "foi@ljmu.ac.uk",
    "foi@london.edu",
    "foi@londonmet.ac.uk",
    "glpd.info.rights@lse.ac.uk",
    "foi@lshtm.ac.uk",
    "foi@lsbu.ac.uk",
    "foi@lboro.ac.uk",
    "foi@mmu.ac.uk",
    "t.kelly@mdx.ac.uk",
    "Rec-Man@ncl.ac.uk",
    "us.foi@northumbria.ac.uk",
    "foi.enquiries@ntu.ac.uk",
    "Freedom-of-Information@open.ac.uk",
    "info.sec@brookes.ac.uk",
    "foi@plymouth.ac.uk",
    "foi@qmu.ac.uk",
    "foi-enquiries@qmul.ac.uk",
    "info.compliance@qub.ac.uk",
    "recordsmanagement@rgu.ac.uk",
    "foi@ram.ac.uk",
    "foi@rca.ac.uk",
    "RCMFoi@rcm.ac.uk",
    "FOI@royalholloway.ac.uk",
    "FOI@RVC.ac.uk",
    "freedomofinformation@soas.ac.uk",
    "foi@shu.ac.uk",
    "freedom.information@solent.ac.uk",
    "FOI@sgul.ac.uk",
    "foi@staffs.ac.uk",
    "foi@swansea.ac.uk",
    "foi@tees.ac.uk",
    "foi@trinitylaban.ac.uk",
    "foi@sm.uwtsd.ac.uk",
    "foi@ucl.ac.uk",
    "foi@abdn.ac.uk",
    "freedom-of-information@bath.ac.uk",
    "legaloffice@beds.ac.uk",
    "foi@contacts.bham.ac.uk",
    "enquiries@bolton.ac.uk",
    "foi@bradford.ac.uk",
    "foi@brighton.ac.uk",
    "Freedom-Information@bristol.ac.uk",
    "foi@admin.cam.ac.uk",
    "dpfoia@uclan.ac.uk",
    "foia@chester.ac.uk",
    "foi@chi.ac.uk",
    "foia@cumbria.ac.uk",
    "foi@derby.ac.uk",
    "freedomofinformation@dundee.ac.uk",
    "foi@uea.ac.uk",
    "foi@uel.ac.uk",
    "recordsmanagement@ed.ac.uk",
    "foi@essex.ac.uk",
    "dataprotection@exeter.ac.uk",
    "foi@gla.ac.uk",
    "freedomofinformation@glos.ac.uk",
    "compliance@greenwich.ac.uk",
    "Foi-request@herts.ac.uk",
    "foi@hud.ac.uk",
    "Foi@hull.ac.uk",
    "foi@kent.ac.uk",
    "foi@leeds.ac.uk",
    "ias@le.ac.uk",
    "compliance@lincoln.ac.uk",
    "foi@liv.ac.uk",
    "records.management@london.ac.uk",
    "foi@manchester.ac.uk",
    "recordsmanager@northampton.ac.uk",
    "freedom-of-information@nottingham.ac.uk",
    "foi@admin.ox.ac.uk",
    "freedom-of-information@port.ac.uk",
    "imps@reading.ac.uk",
    "foi@roehampton.ac.uk",
    "foi@salford.ac.uk",
    "foi@sheffield.ac.uk",
    "freedomofinformation@southwales.ac.uk",
    "foi@soton.ac.uk",
    "foiunit@stir.ac.uk",
    "foi@strath.ac.uk",
    "SUNFOI@sunderland.ac.uk",
    "Freedomofinformation@surrey.ac.uk",
    "foi@sussex.ac.uk",
    "foi@arts.ac.uk",
    "foi@uws.ac.uk",
    "foi@ulster.ac.uk",
    "compliance@wales.ac.uk",
    "foi@sm.uwtsd.ac.uk",
    "infocompliance@warwick.ac.uk",
    "foi@uwe.ac.uk",
    "university.secretary@uwl.ac.uk",
    "foi@westminster.ac.uk",
    "foi@winchester.ac.uk",
    "foi@wlv.ac.uk",
    "foi@worc.ac.uk",
    "foi@york.ac.uk",
    "foi@st-andrews.ac.uk",
    "foi@yorksj.ac.uk"
  ]
}


results = {
  "likely_using_m365" => [],
  "not_using_m365" => []
}

input["emails"].each do |email|
  p email
  domain = email.split('@').last
  if likely_using_m365?(domain)
    p "yes"
    results["likely_using_m365"] << email
  else
    p "yes"
    results["not_using_m365"] << email
  end
end

puts "Likely:  #{results["likely_using_m365"].size} vs Unlikely: #{results["not_using_m365"].size}"

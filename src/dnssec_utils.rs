use dnssec_prover::rr::{Name, RR};
use dnssec_prover::ser::parse_rr_stream;
use dnssec_prover::validation::verify_rr_stream;

use std::time::SystemTime;

use crate::hrn_resolution::HrnResolution;

pub fn resolve_proof(dns_name: &Name, proof: Vec<u8>) -> Result<HrnResolution, &'static str> {
	let rrs = parse_rr_stream(&proof)
		.map_err(|()| "DNS Proof Builder somehow generated an invalid proof")?;
	let verified_rrs = verify_rr_stream(&rrs).map_err(|_| "DNSSEC signatures were invalid")?;

	let clock_err =
		"DNSSEC validation relies on having a correct system clock. It is currently set before 1970.";
	let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_err(|_| clock_err)?;

	if now.as_secs() < verified_rrs.valid_from {
		return Err("Some DNSSEC records are not yet valid. Check your system clock.");
	}
	if now.as_secs() > verified_rrs.expires {
		return Err("Some DNSSEC records are expired. Check your system clock.");
	}

	let resolved_rrs = verified_rrs.resolve_name(dns_name);

	let mut result = None;
	for rr in resolved_rrs {
		if let RR::Txt(txt) = rr {
			let txt = txt.data.as_vec();
			if has_bitcoin_prefix(&txt) {
				if result.is_some() {
					return Err("Multiple TXT records existed for the HRN, which is invalid");
				}
				result = Some(txt);
			}
		}
	}
	let res = result.ok_or("No validated TXT record found")?;
	let result = String::from_utf8(res).map_err(|_| "TXT record contained an invalid string")?;
	Ok(HrnResolution::DNSSEC { proof: Some(proof), result })
}

fn has_bitcoin_prefix(text: &[u8]) -> bool {
	const URI_PREFIX: &[u8] = b"bitcoin:";
	text.len() >= URI_PREFIX.len() && text[..URI_PREFIX.len()].eq_ignore_ascii_case(URI_PREFIX)
}

#[cfg(test)]
mod tests {
	use super::has_bitcoin_prefix;

	#[test]
	fn detects_expected_prefix() {
		assert!(has_bitcoin_prefix(b"bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty"));
		assert!(has_bitcoin_prefix(b"BiTcOiN:pay?amount=1000"));
		assert!(!has_bitcoin_prefix(b"lightning:lnurl"));
		assert!(!has_bitcoin_prefix(b"bitco"));
	}
}

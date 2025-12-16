import dns from 'dns/promises';
import { logger } from '../utils/logger.js';

/**
 * Finds abuse email addresses for hosting provider and registrar
 * This service attempts to find the correct abuse contacts for takedown requests
 */

// Common hosting provider abuse emails - Expanded list
const HOSTING_PROVIDER_ABUSE = {
  // Cloud Providers
  'amazonaws.com': 'abuse@amazonaws.com',
  'aws': 'abuse@amazonaws.com',
  'amazon': 'abuse@amazonaws.com',
  'cloudflare.com': 'abuse@cloudflare.com',
  'google.com': 'abuse@google.com',
  'googlecloud': 'abuse@google.com',
  'gcp': 'abuse@google.com',
  'microsoft.com': 'abuse@microsoft.com',
  'azure': 'abuse@microsoft.com',
  'azure.com': 'abuse@microsoft.com',
  'oracle.com': 'abuse@oracle.com',
  'oraclecloud': 'abuse@oracle.com',
  'ibm.com': 'abuse@us.ibm.com',
  'ibmcloud': 'abuse@us.ibm.com',
  
  // VPS/Cloud Hosting
  'digitalocean.com': 'abuse@digitalocean.com',
  'digitalocean': 'abuse@digitalocean.com',
  'linode.com': 'abuse@linode.com',
  'akamai': 'abuse@akamai.com',
  'akamai.com': 'abuse@akamai.com',
  'vultr.com': 'abuse@vultr.com',
  'vultr': 'abuse@vultr.com',
  'hetzner.com': 'abuse@hetzner.com',
  'hetzner': 'abuse@hetzner.com',
  'ovh.com': 'abuse@ovh.com',
  'ovh': 'abuse@ovh.com',
  'ovh.net': 'abuse@ovh.com',
  'contabo.com': 'abuse@contabo.com',
  'contabo': 'abuse@contabo.com',
  'scaleway.com': 'abuse@scaleway.com',
  'scaleway': 'abuse@scaleway.com',
  'ramnode.com': 'abuse@ramnode.com',
  'ramnode': 'abuse@ramnode.com',
  'linode': 'abuse@linode.com',
  'upcloud.com': 'abuse@upcloud.com',
  'upcloud': 'abuse@upcloud.com',
  'packet.com': 'abuse@packet.com',
  'packet': 'abuse@packet.com',
  'equinix.com': 'abuse@equinix.com',
  'equinix': 'abuse@equinix.com',
  
  // Shared Hosting Providers
  'godaddy.com': 'abuse@godaddy.com',
  'godaddy': 'abuse@godaddy.com',
  'namecheap.com': 'abuse@namecheap.com',
  'namecheap': 'abuse@namecheap.com',
  'bluehost.com': 'abuse@bluehost.com',
  'bluehost': 'abuse@bluehost.com',
  'hostgator.com': 'abuse@hostgator.com',
  'hostgator': 'abuse@hostgator.com',
  'siteground.com': 'abuse@siteground.com',
  'siteground': 'abuse@siteground.com',
  'dreamhost.com': 'abuse@dreamhost.com',
  'dreamhost': 'abuse@dreamhost.com',
  'ionos.com': 'abuse@ionos.com',
  'ionos': 'abuse@ionos.com',
  '1and1.com': 'abuse@ionos.com',
  '1and1': 'abuse@ionos.com',
  '1&1': 'abuse@ionos.com',
  'hostinger.com': 'abuse@hostinger.com',
  'hostinger': 'abuse@hostinger.com',
  'a2hosting.com': 'abuse@a2hosting.com',
  'a2hosting': 'abuse@a2hosting.com',
  'inmotionhosting.com': 'abuse@inmotionhosting.com',
  'inmotionhosting': 'abuse@inmotionhosting.com',
  'inmotion': 'abuse@inmotionhosting.com',
  'wpengine.com': 'abuse@wpengine.com',
  'wpengine': 'abuse@wpengine.com',
  'kinsta.com': 'abuse@kinsta.com',
  'kinsta': 'abuse@kinsta.com',
  'liquidweb.com': 'abuse@liquidweb.com',
  'liquidweb': 'abuse@liquidweb.com',
  'mediatemple.net': 'abuse@mediatemple.net',
  'mediatemple': 'abuse@mediatemple.net',
  'mt': 'abuse@mediatemple.net',
  
  // European Hosting
  'strato.com': 'abuse@strato.com',
  'strato': 'abuse@strato.com',
  'one.com': 'abuse@one.com',
  'one': 'abuse@one.com',
  'fasthosts.co.uk': 'abuse@fasthosts.co.uk',
  'fasthosts': 'abuse@fasthosts.co.uk',
  'tsohost.co.uk': 'abuse@tsohost.co.uk',
  'tsohost': 'abuse@tsohost.co.uk',
  
  // Asian Hosting
  'alibaba.com': 'abuse@alibaba.com',
  'alibabacloud': 'abuse@alibaba.com',
  'aliyun.com': 'abuse@aliyun.com',
  'tencent.com': 'abuse@tencent.com',
  'tencentcloud': 'abuse@tencent.com',
  'baidu.com': 'abuse@baidu.com',
  
  // CDN Providers
  'fastly.com': 'abuse@fastly.com',
  'fastly': 'abuse@fastly.com',
  'cloudfront': 'abuse@amazonaws.com',
  'cloudfront.net': 'abuse@amazonaws.com',
  'maxcdn.com': 'abuse@maxcdn.com',
  'maxcdn': 'abuse@maxcdn.com',
  'keycdn.com': 'abuse@keycdn.com',
  'keycdn': 'abuse@keycdn.com',
  'bunnycdn.com': 'abuse@bunnycdn.com',
  'bunnycdn': 'abuse@bunnycdn.com',
  
  // Domain Registrars (also hosting)
  'name.com': 'abuse@name.com',
  'name': 'abuse@name.com',
  'enom.com': 'abuse@enom.com',
  'enom': 'abuse@enom.com',
  'tucows.com': 'abuse@tucows.com',
  'tucows': 'abuse@tucows.com',
  'networksolutions.com': 'abuse@networksolutions.com',
  'networksolutions': 'abuse@networksolutions.com',
  'register.com': 'abuse@register.com',
  'register': 'abuse@register.com',
  'dynadot.com': 'abuse@dynadot.com',
  'dynadot': 'abuse@dynadot.com',
  'porkbun.com': 'abuse@porkbun.com',
  'porkbun': 'abuse@porkbun.com',
  'namesilo.com': 'abuse@namesilo.com',
  'namesilo': 'abuse@namesilo.com',
  'namebright.com': 'abuse@namebright.com',
  'namebright': 'abuse@namebright.com',
  
  // Other Providers
  'rackspace.com': 'abuse@rackspace.com',
  'rackspace': 'abuse@rackspace.com',
  'softlayer.com': 'abuse@softlayer.com',
  'softlayer': 'abuse@softlayer.com',
  'joyent.com': 'abuse@joyent.com',
  'joyent': 'abuse@joyent.com',
  'serverpilot.io': 'abuse@serverpilot.io',
  'serverpilot': 'abuse@serverpilot.io',
  'runcloud.io': 'abuse@runcloud.io',
  'runcloud': 'abuse@runcloud.io',
  'cpanel.net': 'abuse@cpanel.net',
  'cpanel': 'abuse@cpanel.net',
  'plesk.com': 'abuse@plesk.com',
  'plesk': 'abuse@plesk.com',
};

// Common registrar abuse emails
const REGISTRAR_ABUSE = {
  'godaddy': 'abuse@godaddy.com',
  'namecheap': 'abuse@namecheap.com',
  'name.com': 'abuse@name.com',
  'google domains': 'abuse@google.com',
  'cloudflare': 'abuse@cloudflare.com',
  'enom': 'abuse@enom.com',
  'tucows': 'abuse@tucows.com',
  'network solutions': 'abuse@networksolutions.com',
  '1&1 ionos': 'abuse@ionos.com',
  'ionos': 'abuse@ionos.com',
};

/**
 * Extract domain from URL
 */
export function extractDomain(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname.replace(/^www\./, '');
  } catch (error) {
    logger.warn(`Failed to extract domain from URL: ${url}`, error);
    return null;
  }
}

/**
 * Resolve domain to IP address
 */
export async function resolveDomainToIP(domain) {
  try {
    const addresses = await dns.resolve4(domain);
    return addresses[0] || null;
  } catch (error) {
    // Try IPv6 if IPv4 fails
    try {
      const addresses = await dns.resolve6(domain);
      return addresses[0] || null;
    } catch (error2) {
      logger.warn(`Failed to resolve domain ${domain} to IP:`, error.message);
      return null;
    }
  }
}

/**
 * Perform reverse DNS lookup to find hosting provider
 */
export async function findHostingProvider(ip) {
  try {
    const hostnames = await dns.reverse(ip);
    if (hostnames.length > 0) {
      const hostname = hostnames[0].toLowerCase();
      
      // Check against known hosting providers
      for (const [provider, email] of Object.entries(HOSTING_PROVIDER_ABUSE)) {
        if (hostname.includes(provider)) {
          return {
            provider: provider,
            abuseEmail: email,
            hostname: hostname,
            method: 'reverse_dns'
          };
        }
      }
      
      // Extract provider from hostname (e.g., ec2-1-2-3-4.compute-1.amazonaws.com -> amazonaws)
      const parts = hostname.split('.');
      if (parts.length >= 2) {
        const domain = parts.slice(-2).join('.');
        if (HOSTING_PROVIDER_ABUSE[domain]) {
          return {
            provider: domain,
            abuseEmail: HOSTING_PROVIDER_ABUSE[domain],
            hostname: hostname,
            method: 'reverse_dns'
          };
        }
      }
    }
    
    return null;
  } catch (error) {
    logger.warn(`Failed reverse DNS lookup for IP ${ip}:`, error.message);
    return null;
  }
}

/**
 * Check if domain uses Cloudflare nameservers
 */
export async function checkCloudflare(domain) {
  try {
    const nsRecords = await dns.resolveNs(domain);
    const cloudflareNS = nsRecords.some(ns => 
      ns.toLowerCase().includes('cloudflare')
    );
    
    if (cloudflareNS) {
      return {
        isCloudflare: true,
        abuseEmail: 'abuse@cloudflare.com',
        nameservers: nsRecords
      };
    }
    
    return { isCloudflare: false };
  } catch (error) {
    logger.warn(`Failed to check Cloudflare for ${domain}:`, error.message);
    return { isCloudflare: false };
  }
}

/**
 * Find registrar abuse email (simplified - would need WHOIS API in production)
 * This is a basic implementation - for production, use a WHOIS API service
 */
export function findRegistrarAbuse(domain) {
  // Extract TLD and common registrar patterns
  const parts = domain.split('.');
  const tld = parts[parts.length - 1];
  
  // This is a simplified lookup - in production, use WHOIS API
  // Common patterns: abuse@[registrar].com
  // For now, return null and let the caller use a default
  
  return null;
}

/**
 * Main function to find all abuse emails for a domain
 */
export async function findAbuseEmails(url) {
  const domain = extractDomain(url);
  if (!domain) {
    return {
      domain: null,
      hostingProvider: null,
      registrar: null,
      cloudflare: null,
      emails: []
    };
  }

  const results = {
    domain: domain,
    hostingProvider: null,
    registrar: null,
    cloudflare: null,
    emails: []
  };

  try {
    // 1. Check Cloudflare (fastest check)
    try {
      const cloudflareCheck = await checkCloudflare(domain);
      if (cloudflareCheck.isCloudflare) {
        results.cloudflare = {
          abuseEmail: cloudflareCheck.abuseEmail,
          nameservers: cloudflareCheck.nameservers
        };
        results.emails.push({
          type: 'cloudflare',
          email: cloudflareCheck.abuseEmail,
          reason: 'Domain uses Cloudflare nameservers'
        });
      }
    } catch (cfError) {
      logger.debug(`[Abuse Emails] Cloudflare check failed for ${domain}:`, cfError.message);
    }

    // 2. Resolve domain to IP
    try {
      const ip = await resolveDomainToIP(domain);
      if (ip) {
        // 3. Find hosting provider via reverse DNS
        try {
          const hostingProvider = await findHostingProvider(ip);
          if (hostingProvider) {
            results.hostingProvider = hostingProvider;
            results.emails.push({
              type: 'hosting_provider',
              email: hostingProvider.abuseEmail,
              provider: hostingProvider.provider,
              reason: `Hosting provider detected via reverse DNS: ${hostingProvider.hostname}`
            });
          }
        } catch (hostingError) {
          logger.debug(`[Abuse Emails] Hosting provider detection failed:`, hostingError.message);
        }
      }
    } catch (dnsError) {
      logger.debug(`[Abuse Emails] DNS resolution failed for ${domain}:`, dnsError.message);
    }

    // 4. Try to find registrar (simplified - would use WHOIS API)
    try {
      const registrarAbuse = findRegistrarAbuse(domain);
      if (registrarAbuse) {
        results.registrar = registrarAbuse;
        results.emails.push({
          type: 'registrar',
          email: registrarAbuse.abuseEmail,
          reason: 'Domain registrar abuse contact'
        });
      }
    } catch (registrarError) {
      logger.debug(`[Abuse Emails] Registrar lookup failed:`, registrarError.message);
    }

    // 5. Add APWG for tracking (always include)
    results.emails.push({
      type: 'tracking',
      email: 'report@apwg.org',
      reason: 'Anti-Phishing Working Group - for tracking and coordination'
    });

    logger.info(`[Abuse Emails] Found ${results.emails.length} abuse contacts for ${domain}`);
    
    return results;
  } catch (error) {
    logger.error(`Error finding abuse emails for ${domain}:`, error);
    // Still return APWG email as fallback
    results.emails.push({
      type: 'tracking',
      email: 'report@apwg.org',
      reason: 'Fallback - APWG tracking'
    });
    return results;
  }
}


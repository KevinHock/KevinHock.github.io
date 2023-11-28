---
layout: post
toc: true
title: "Preventing Accidental Internet-Exposure of AWS Resources (Part 1: VPC)"
---

[Many AWS customers have suffered breaches](https://github.com/ramimac/aws-customer-security-incidents#background) due to exposing resources to the [Internet by accident](https://maia.crimew.gay/posts/how-to-hack-an-airline/). This three-part series walks through different ways to mitigate that risk.

## About The Problem

There are many ways to make resources public in AWS. [github.com/SummitRoute/aws_exposable_resources](https://github.com/SummitRoute/aws_exposable_resources#aws-exposable-resources) was created specifically to maintain a list of all AWS resources that can be publicly exposed and how. Here, we will focus on network access.

Preventing public network access to AWS resources is vital because without network access – all an attacker can leverage is the AWS API – making this arguably the highest ROI attack surface reduction you can make.

This first post discusses resources exclusively in a VPC (EC2 instances, ELBs, RDS databases, etc.).

Ideally, you can look at your AWS organization structure from a 1000-foot view and know which subtree of accounts / OUs can have publicly accessible VPCs.

What Good Looks Like:
![alt text](https://i.imgur.com/cVFUpkJ.png)

## Solving The Problem

You can implement this by banning `"ec2:CreateInternetGateway"` in subaccounts via SCP.[^2111]

It works because although there are many ways an accidental Internet-exposure might happen -- for VPCs at least -- every way requires an Internet Gateway (IGW). E.g.

![alt text](https://i.imgur.com/1e4M8z4.gif)

Or:       
![alt text](https://i.imgur.com/gyXZz2E.gif)

[^2111]: Along with deleting all the IGWs/VPCs that AWS makes by default in new accounts.

With IGWs banned, you can hand subaccounts over to customers, and they will never be able to make public-facing load balancers or EC2 instances regardless of their IAM permissions!

There is only one complication.

In AWS: <ins>Egress to the Internet is tightly coupled with Ingress from the Internet</ins>. In most cases, only the former is required (for example, downloading libraries, patches, or OS updates).

They are tightly coupled because both require an Internet Gateway (IGW).

The Egress use-case typically looks like:
![alt text](https://i.imgur.com/vKsdNOh.png)

## Supporting Egress in Private VPC Accounts

To support the Egress use-case, you must ensure your network architecture tightly couples NAT with an Internet Gateway by, e.g., giving subaccounts a paved path to a NAT Gateway in another account. Your options:
1. [Centralized Egress via Transit Gateway (TGW)](#option-1-centralized-egress-via-transit-gateway-tgw)
2. [Centralized Egress via PrivateLink (or VPC Peering) with Proxy](#option-2-centralized-egress-via-privatelink-or-vpc-peering-with-proxy)
3. [Centralized Egress via Gateway Load Balancer (GWLB) with Firewall](#option-3-centralized-egress-via-gateway-load-balancer-gwlb-with-firewall)
4. [VPC Sharing](#option-4-vpc-sharing)
5. [IPv6 for Egress](#option-5-ipv6-for-egress)

Hopefully, one of these options will align with the goals of your networking team.

My recommendation:
![alt text](https://i.imgur.com/V7IYxO9.png)

### Option 1: Centralized Egress via Transit Gateway (TGW)

TGW is the most common implementation and probably the best. If money is no issue for you, go this route.

![alt text](https://i.imgur.com/alRH2hN.png) 

AWS first wrote about this [in 2019](https://aws.amazon.com/blogs/networking-and-content-delivery/creating-a-single-internet-exit-point-from-multiple-vpcs-using-aws-transit-gateway/) and lists it under their prescriptive guidance as [Centralized Egress](https://docs.aws.amazon.com/prescriptive-guidance/latest/transitioning-to-multiple-aws-accounts/centralized-egress.html).

As you can see, each VPC in a subaccount has a route table with `0.0.0.0/0` destined traffic sent to a TGW in another account, where an IGW does live.

#### A Note On Cost

Your NAT Gateway cost, arguably AWS’s most notoriously expensive networking component, will be reduced with this option.

On one hand, [AWS states](https://docs.aws.amazon.com/whitepapers/latest/building-scalable-secure-multi-vpc-network-infrastructure/centralized-egress-to-internet.html):

>Deploying a NAT gateway in every AZ of every spoke VPC can become cost-prohibitive because you pay an hourly charge for every NAT gateway you deploy, so centralizing could be a viable option.

On the other hand, they also say:

>In some edge cases, when you send massive amounts of data through a NAT gateway from a VPC, keeping the NAT local in the VPC to avoid the Transit Gateway data processing charge might be a more cost-effective option.

Sending massive amounts of data through a NAT Gateway should be avoided anyway.
[S3](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-s3.html), [Splunk](https://www.splunk.com/en_us/blog/platform/announcing-aws-privatelink-support-on-splunk-cloud-platform.html), [Honeycomb](https://docs.honeycomb.io/integrations/aws/aws-privatelink/), and similar companies[^1350] have VPC endpoints you can utilize to lower NAT Gateway data processing charges.

[^1350]: Some companies with agents meant to be deployed on EC2s do not offer a VPC endpoint or charge an exorbitant fee to use one; [perhaps](https://sso.tax/) a [wall](https://fido.fail/) of [shame](https://github.com/SummitRoute/imdsv2_wall_of_shame#imdsv2-wall-of-shame) can be made. Chime [mentioned](https://medium.com/life-at-chime/how-we-reduced-our-aws-bill-by-seven-figures-5144206399cb): `"Although our vendor offers PrivateLink, they have also chosen to monetize it, charging so much for access to the feature that it was not a viable option."`


The following is a graph [generated with Python](https://gist.github.com/KevinHock/06739af9993165248d97046d0cecc053). As you can see, at, e.g., 20 VPCs, you'd need to be sending over 55 TB for centralized egress to be more expensive. It only gets more worthwhile the more VPCs you add.
![alt text](https://i.imgur.com/aE3L89N.png)

Chime ([the Fintech company](https://www.chime.com/)) is one of the edge cases AWS mentioned; Chime wrote about _petabytes_ of data and [saved seven figures getting rid of NAT Gateways](https://medium.com/life-at-chime/how-we-reduced-our-aws-bill-by-seven-figures-5144206399cb). For them, TGW would break the bank. [1 PB of data transferred would require 324 VPCs to break even, 2 PB would require 646 VPCs](https://i.imgur.com/c6OeoqH.png).

See [the FAQ](#can-you-walk-through-the-cost-details-around-option-1) for a verbose example.

### Option 2: Centralized Egress via PrivateLink (or VPC Peering) with Proxy

![alt text](https://i.imgur.com/vg9rcTE.png)

PrivateLink ([and VPC Peering](#why-is-vpc-peering-not-a-straightforward-option)) are mostly non-options.

The reason for this is as follows. When you make an interface VPC endpoint with AWS PrivateLink, a "[requester-managed network interface](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/requester-managed-eni.html)" is created with "[source/destination checking](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html#eni-basics)" enabled.[^84415] Due to this check, traffic destined for the Internet but sent to that network interface is dropped before it travels cross-account.

[^84415]: The "requester" is AWS, as you can see by [the mysterious `"727180483921"` account ID](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/requester-managed-eni.html). Since you do not manage it, you cannot disable the [source/destination checking](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html#eni-basics)

However, suppose you are willing to do a lot of heavy lifting that is orthogonal to AWS primitives.

In that case, you _can_ use these with [an outbound proxy](https://eng.lyft.com/internet-egress-filtering-of-services-at-lyft-72e99e29a4d9) to accomplish centralized egress. This works because the destination IP of outbound traffic won't be the Internet, but a private IP, due to deploying, e.g., iptables to re-route Internet-destined traffic on every host.

Some reasons you may not want to do this are:
- Significant effort
- It won't be possible for all subaccount types, such as sandbox accounts. (Where requiring `iptables` and a proxy are too heavyweight.)
- Egress filtering is a lower priority than preventing accidental Internet-exposure. So, tightly coupling the two and needing to set up a proxy first may not make strategic sense.
- If something goes wrong on the host, the lost traffic will not appear in VPC flow logs [^98] or traffic mirroring logs.[^985] The DNS lookups will appear in Route53 query logs, but that's it.

With that said, AWS does not have a primitive to perform Egress filtering,[^99] so you will eventually have to implement Egress filtering via a proxy or a firewall. Therefore, in non-sandbox accounts, you could go with this option.

[^98]: [Flow log limitations](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html#flow-logs-limitations) do not state "Internet-bound traffic sent to a peering connection" or "Internet-bound traffic sent to a VPC interface endpoint." under `The following types of traffic are not logged:`. After testing, I believe these are likely omitted due to not being a proper use-case.

[^985]: A peering connection cannot be selected as a [traffic mirror source or target](https://docs.aws.amazon.com/vpc/latest/mirroring/traffic-mirroring-targets.html), but a network interface can. However, only an ENI belonging to an EC2 instance can be a mirror source, not an ENI belonging to an Interface endpoint. The documentation doesn't mention this anywhere I could find.

[^99]: It has [AWS Network Firewall](https://aws.amazon.com/network-firewall/faqs/), which is [just managed Suricata](https://docs.suricata.io/en/latest/rules/tls-keywords.html) and can be fooled via SNI spoofing. So it is, at best, a stepping stone to keep an inventory of your Egress traffic if you can’t get a proxy or real firewall running short-term and [are not using TLS 1.3 with encrypted client hello (ECH) or encrypted SNI (ESNI)](https://docs.aws.amazon.com/network-firewall/latest/developerguide/tls-inspection-considerations.html).

### Option 3: Centralized Egress via Gateway Load Balancer (GWLB) with Firewall

[GWLB](https://aws.amazon.com/blogs/aws/introducing-aws-gateway-load-balancer-easy-deployment-scalability-and-high-availability-for-partner-appliances/) is a service intended to enable the deployment of virtual appliances in the form of firewalls, intrusion detection/prevention systems, and deep packet inspection systems. The appliances get sent the original traffic [encapsulated via the Geneve protocol](https://aws.amazon.com/blogs/networking-and-content-delivery/integrate-your-custom-logic-or-appliance-with-aws-gateway-load-balancer/).[^99328]

[^99328]: The usual suspects [Aidan Steele](https://awsteele.com/blog/2022/01/20/aws-gwlb-deep-packet-manipulation.html), [Luc van Donkersgoed](https://web.archive.org/web/20220129101637/https://www.sentiatechblog.com/geneveproxy-an-aws-gateway-load-balancer-reference-application), and [Corey Quinn](https://www.lastweekinaws.com/blog/what-i-dont-get-about-the-aws-gateway-load-balancer/) have written about GWLB.

In the [previous section](#option-2-centralized-egress-via-privatelink-or-vpc-peering-with-proxy), I wrote that PrivateLink was mostly a non-option because interface endpoint ENIs have  "[Source/destination checking](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html#eni-basics)" enabled.

Gateway Load Balancer endpoint ENIs _have this check disabled_  to support their intended use-cases. This enables us to send `0.0.0.0/0` destined traffic to a GWLBe [as we did for the TGW in Option 1](#option-1-centralized-egress-via-transit-gateway-tgw).

![alt text](https://i.imgur.com/tIQaTa0.png)
(No NAT Gateway is necessary here, as the firewall is running in a public subnet and performing NAT. [AWS](https://aws.amazon.com/blogs/networking-and-content-delivery/best-practices-for-deploying-gateway-load-balancer/) and [others](https://networkgeekstuff.com/networking/basic-load-balancer-scenarios-explained/) call this two-arm mode.)

The firewall must support Geneve encapsulation, be invulnerable to SNI spoofing, fast, reliable, not [susceptible to IP address mismatches](https://chasersystems.com/discriminat/faq/#are-the-out-of-band-dns-lookups-susceptible-to-ip-address-mismatches), and preferably perform NAT to eliminate the need for NAT Gateways, so building an open-source alternative is not easy.

Regarding specific vendors, [DiscrimiNAT](https://github.com/ChaserSystems/terraform-aws-discriminat-gwlb#deployment-examples) seems much easier to configure compared to e.g. Palo Alto Firewall,[^99351] as all you do is [add FQDNs to security group descriptions](https://chasersystems.com/docs/discriminat/aws/quick-start/#viii-configuring-a-whitelist). However, DiscrimiNAT would need to add subaccount support for the diagram above to function to read the security groups in the 'spoke' account.

[^99351]: These are just my 1st impressions. [Dhruv](https://github.com/new23d) didn't pay me to write this.

### Option 4: VPC Sharing

VPC Sharing is a tempting, simple, and little-known option.[^996]

[^996]: Shout out to [Aidan Steele](https://awsteele.com/blog/2022/01/02/shared-vpcs-are-underrated.html) and [Stephen Jones](https://sjramblings.io/unlock-the-hidden-power-of-vpc-sharing-in-aws) for writing their thoughts on VPC Sharing.

You can simply make a VPC in your networking account and share private subnets to subaccounts.

![alt text](https://i.imgur.com/4OojfzP.png)

The main problem is that there will _still be an Internet Gateway in the VPC_.

Unless you also used one of the other options, like a TGW:[^12202]
![alt text](https://i.imgur.com/aYyKrH1.png)

[^12202]: 20 bucks per TB in data processing costs + \~$73.04 a month.

Assuming you don't want to pay for TGW, you can ban actions that would explicitly give an instance in a private subnet a public IP.[^220220]

[^220220]: See [the FAQ](#what-happens-if-an-ec2-instance-in-a-private-subnet-gets-a-public-ip) for what it means to have an EC2 with a public IP in a private subnet.

These actions are [`ec2:RunInstances` with the `"ec2:AssociatePublicIpAddress` condition key set to `"true"`](https://github.com/ScaleSec/terraform_aws_scp/blob/521ac29d712a6ebb51feb6f11b56e6c40b61bada/security_controls_scp/modules/ec2/deny_public_ec2_ip.tf#L5-L29) and EIP-related IAM actions such as `ec2:AssociateAddress`.

Then, the only problem is AWS services that treat the presence of an IGW as a 'welcome mat' to make something face the Internet; [Global Accelerator](https://aws.amazon.com/blogs/networking-and-content-delivery/accessing-private-application-load-balancers-and-instances-through-aws-global-accelerator/) is an example. These are not a big deal because, regardless, you have to deal with the ‘hundreds of AWS services’ problem holistically; many other services don’t require an IGW to make Internet-facing resources.

I discuss addressing the risk of 'hundreds of AWS services' in the next part of the series.

#### ENI Limitations Warning

On a large scale, you probably don't want to use Shared VPCs.

There [are limits](https://aws.amazon.com/about-aws/whats-new/2022/10/amazon-virtual-private-cloud-vpc-now-supports-new-cloudwatch-metrics-measure-track-network-address-usage/) of 256,000 network addresses in a single VPC and 512,000 network addresses when peered within a region, in addition to [HyperPlane ENI limits](https://aws.plainenglish.io/dealing-with-you-have-exceeded-the-maximum-limit-for-hyperplane-enis-for-your-account-223147e7ab64).

#### Organization Migration Implications

In the [Shareable AWS Resources](https://docs.aws.amazon.com/ram/latest/userguide/shareable.html#shareable-vpc) page of the AWS RAM documentation, `ec2:Subnet` is one of 7 resource types marked as

> Can share with ***only*** AWS accounts in its own organization.

Meaning you can never perform an AWS organization migration in the future.

If you are like most AWS customers:
- The Management Account of your AWS Organization has most of your resources in it
- You want to follow Best Practices[^996221] and have an empty Management Account
- It is infeasible to 'empty' out the current management account over time

[^996221]: See Stage 1 of Scott's [AWS Security Maturity Roadmap](https://summitroute.com/downloads/aws_security_maturity_roadmap-Summit_Route.pdf), for example.

Then, you will need to perform an org migration in the future and should stay away from VPC Sharing for any environments you can't easily delete.

However, suppose you are willing to risk a production outage... (Particularly if you do not use ASGs or Load Balancers, which will lose access to the subnets.) The NAT Gateway will remain functional, according to AWS.

See

>Scenario 5: VPC Sharing across multiple accounts

from [Migrating accounts between AWS Organizations, a network perspective](https://aws.amazon.com/blogs/networking-and-content-delivery/migrating-accounts-between-aws-organizations-from-a-network-perspective/) by Tedy Tirtawidjaja for more information.

### Option 5: IPv6 for Egress

Remember how I said, "In AWS: Egress to the Internet is tightly coupled with Ingress from the Internet" above? For IPv6, that's a lie.

IPv6 addresses are globally unique and, therefore, public by default. Due to this, AWS created the primitive of an [Egress-only Internet Gateway](https://docs.aws.amazon.com/vpc/latest/userguide/egress-only-internet-gateway.html) (EIGW).

Unfortunately, with an EIGW, there is no way to connect IPv4-only destinations, so if you need to – which is likely – go with one of the other options.

![alt text](https://i.imgur.com/wtuaa71.png)

#### More details around IPv4-only Destinations

As Sébastien Stormacq wrote in [Let Your IPv6-only Workloads Connect to IPv4 Services](https://aws.amazon.com/blogs/aws/let-your-ipv6-only-workloads-connect-to-ipv4-services/), you need only add a route table entry and set `--enable-dns64` on subnets to accomplish this -- but you unfortunately still need an IGW.

`--enable-dns64` makes it so DNS queries to the Amazon-provided DNS Resolver will return synthetic IPv6 addresses for IPv4-only destinations with the well-known `64:ff9b::/96` prefix. The route table entry makes traffic with that prefix go to the NAT Gateway.

The problem is the NAT Gateway then needs an IGW to communicate with the destination, so one of the [other options](https://d1.awsstatic.com/architecture-diagrams/ArchitectureDiagrams/IPv6-reference-architectures-for-AWS-and-hybrid-networks-ra.pdf) becomes necessary.

### Tradeoffs

Criteria                   | TGW                                    | PrivateLink + Proxy                 | GWLB + Firewall                       | VPC Sharing                           | IPv6-Only
-------------------------- | ---------------------------------------| ------------------------------------| --------------------------------------| ---------
AWS Billing Cost           | <span style="color:red">High</span>    | Low                                 | <span style="color:red">High</span>   | Low                                   | Low
Complexity*                | Medium                                 | <span style="color:red">High</span> | Medium                                | Low                                   | Medium
Scalability*               | High                                   | High                                | High                                  | Low                                   | Medium
Flexibility*               | High                                   | High                                | High                                  | Medium                                | <span style="color:red">Lowest</span>
Filtering Granularity      | None                                   | FQDN (or URL Path\*\*)              | FQDN (or URL Path\*\*)                                | None                                 | None
Will Prevent Org Migration | False                                  | False                               | False                                 | <span style="color:red">True</span>   | False

\* = YMMV

\*\* = URL path is only available to filter on if MITM is performed.[^91512]

[^91512]: See the ["Man-in-the-Middle" section](https://eng.lyft.com/internet-egress-filtering-of-services-at-lyft-72e99e29a4d9) of Lyft's post, for some thoughts around this.

## FAQ

### Can you walk through the cost details around Option 1?

_Note: This assumes US East, 100 VPCs, and 3 AZs. If you want to change these variables, see the [Python gist](https://gist.github.com/KevinHock/06739af9993165248d97046d0cecc053) that made [the graph above](#option-1-centralized-egress-via-transit-gateway-tgw)._

#### Cost Example: No Centralized Egress

**Hourly Costs**

> For 1 NAT Gateway: $0.045 [per hour](https://aws.amazon.com/vpc/pricing/). They are also AZ-specific. So that is 3 availability zones * [730.48](https://techoverflow.net/2022/12/21/how-many-hours-are-there-in-each-month/) hours a month * $0.045 = $98.61 per month per VPC.

> Let's say you have 100 VPCs split across various different accounts/regions.

> That is $9,861 a month, or $118,332 annually!

**Data Processing Costs**

> For NAT Gateway: $0.045 [per GB of data processed](https://aws.amazon.com/vpc/pricing/)

> 100 GB a month would be $4.50.

> 1 TB a month would be $45.

> 10 TB a month would be $450.


#### Cost Example: Centralized Egress

**Hourly Costs**

> 1 NAT Gateway: $98.61 a month

> 1 Transit Gateway: with (100 + 1) VPC attachments, at 0.05 [per hour](https://aws.amazon.com/transit-gateway/pricing/). 101 * 730.48 * 0.05  = $3,688.92 per month.

> 9,861-(98.61+3,688.92) = A cost savings of 6,073.47 a month on hourly costs!

**Data Processing Costs**

> Same as the above + the TGW data processing charge.

> At $0.02 [per GB of data processed](https://aws.amazon.com/transit-gateway/pricing/), that is only 20 bucks per TB of data!

> In conclusion, for centralized egress to cost more, you’d need to send more than 303.67 TB.

### Why is VPC peering not a straightforward option?

The short answer is that VPC peering is not transitive, so it is not designed for you to be able to 'hop' through an IGW via it. If you change your VPC route table to send Internet-destined traffic to a VPC peering connection, the traffic won't pass through.

AWS lists this under [VPC peering limitations](https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-basics.html#vpc-peering-limitations):

> - If VPC A has an internet gateway, resources in VPC B can't use the internet gateway in VPC A to access the Internet.

> - If VPC A has a NAT device that provides Internet access to subnets in VPC A, resources in VPC B can't use the NAT device in VPC A to access the Internet.

A [longer explanation is](https://www.reddit.com/r/aws/comments/1625r2h/comment/jxxodvl):

> AWS has specific design principles and limitations for VPC peering to ensure security and network integrity. One of these limitations is that edge-to-edge routing is not supported over VPC peering connections. VPC connections are specifically designed to be non-transitive.

>This means resources in one VPC cannot access the Internet via an internet gateway or a NAT device in a peer VPC. AWS does not propagate packets destined for the Internet from one VPC to another over a peering connection, even if you try configuring NAT at the instance level.

>The primary reason for this limitation is to maintain a clear network boundary and enforce security policies. If AWS allowed traffic from VPC B to Egress to the Internet through VPC A's NAT gateway, it would essentially make VPC A a transit VPC, which breaks the AWS design principle of VPC peering as a non-transitive relationship.

### How much cheaper is VPC Sharing than TGW?

_Assuming you would have 50 spoke VPCs and were in US East._

If you are making 1 giant VPC, and sharing different subnets to each subaccount, then both options would have 1 NAT Gateway. The only difference is a TGW:

> 1 Transit Gateway: with (50 + 1) VPC attachments, at 0.05 [per hour](https://aws.amazon.com/transit-gateway/pricing/). 51 * 730.48 * 0.05  = $1,862.72 per month.

> At $0.02 [per GB of data processed](https://aws.amazon.com/transit-gateway/pricing/), that is 20 bucks a month more per TB of data!

Assuming 1 TB of data is processed a month, that is $1,882.72 more.

#### VPC Endpoint Costs

If you wanted to use VPC endpoints across all VPCs, you'd have to pay 50x more for them with TGW.

Those are $0.01 per hour per availability zone = $22 per month per service per VPC. So, e.g., `SQS, SNS, KMS, STS, X-Ray, ECR, ECS` across all VPCs, is $154 a month with sharing.

Vs. $7,700 a month with 50 separate VPCs!

### How do I access my machines if they are all in private subnets?

Use [SSM](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-sessions-start.html) or a similar product.

### How do I decide between a proxy vs. a firewall for egress filtering?

[Chaser Systems has a good "pros- and cons-" bakeoff](https://chasersystems.com/blog/proxy-on-gcp-harder-better-faster-stronger/#maybe-a-proxy-less-solution) between the 2 types, but it only compares DiscrimiNAT and Squid.

Overall, there is a dearth of information about baking off specific solutions. I would love to see someone write a post around this.

The options I know about are as follows.

Proxies:
- [Envoy](https://github.com/envoyproxy/envoy) (Used by e.g. [Lyft](https://eng.lyft.com/internet-egress-filtering-of-services-at-lyft-72e99e29a4d9), [Palantir](https://blog.palantir.com/using-envoy-for-egress-traffic-8524d10b5ee2))
- [Smokescreen](https://github.com/stripe/smokescreen) (Used by e.g. Stripe and presumably [HashiCorp](https://github.com/stripe/smokescreen/pull/140))
- [Squid](https://en.wikipedia.org/wiki/Squid_(software)) (The older "OG" solution first made in 1996. Used by many e.g. banks.)

Firewalls:
- [Chaser Systems DiscrimiNAT](https://chasersystems.com/)
- Aviatrix
- Palo Alto
- Others (Cisco, maybe?)

I do not know if Aviatrix/Palo Alto/Others are [bypassable like AWS Network Firewall is](https://chasersystems.com/discriminat/comparison/aws-network-firewall/), but it is something to watch out for.

### What happens if an EC2 instance in a private subnet gets a public IP?

You can send packets to it from the Internet. However, the EC2 can't respond over TCP.

Incoming traffic first hits the IGW, then the EC2. Nothing else is checked, assuming the NACL and security group allow it.

As for why it cannot respond to traffic, that is more interesting!

For a private subnet, the route table -- which is only consulted for outgoing traffic -- will have a path to a NAT Gateway, not the IGW. So response packets will reach the NAT Gateway, [which does connection/flow tracking](https://www.youtube.com/watch?app=desktop&v=UP7wDBjZ37o&t=35m20s),[^91426] and get dropped because there is no existing connection.[^9133]

[^91426]: According to that re:Invent session from [Colm MacCárthaigh](https://twitter.com/colmmacc?lang=en), and me testing [ACK scanning](https://nmap.org/book/scan-methods-ack-scan.html#:~:text=ACK%20scan%20is%20enabled%20by,both%20return%20a%20RST%20packet.) does not work through a NAT Gateway.

[^9133]: A **3rd** shout out to Aidan Steele, who [wrote about this in another context](https://twitter.com/__steele/status/1572752577648726016), and has [visuals / code here](https://github.com/aidansteele/matconnect#matconnect).

If the EC2 has UDP ports open, an attacker can receive responses, and you have a security problem. (A NACL will not help, as an Ingress deny rule blocking the Internet from hitting the EC2 will also block responses from the Internet to Egress Traffic.)

## Conclusion

Let me know how it goes limiting your Internet-exposed attack surface in an easy to understand, secure-by-default way.[^92442]

[^92442]: Also, special thanks to a few cloud security community members for being kind enough to review earlier drafts of this post.

You might still get breached, but hopefully in a more interesting way.

The next part of this series covers handling the hundreds of other AWS services beyond just those in a VPC.

## Footnotes

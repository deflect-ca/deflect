from pyaml_env import parse_config
import dns.resolver

if __name__ == '__main__':

    IP_A = '1.2.3.4'
    IP_B = '5.6.7.8'
    base_names_to_sites = parse_config("input/current/old-sites.yml")["remap"]

    all_names_and_types = []

    for base_name, site in base_names_to_sites.items():
        if not site['ns_on_deflect']:
            continue
        for extra_name, extra_ds in site.get("dns_records", {}).items():
            if extra_name == "@":
                continue
            for extra_d in extra_ds:
                all_names_and_types.append({'name': f"{extra_name}.{base_name}", 'type': extra_d['type']})

    print(len(all_names_and_types))

    old_resolver = dns.resolver.Resolver()
    old_resolver.nameservers = [IP_A]

    new_resolver = dns.resolver.Resolver()
    new_resolver.nameservers = [IP_B]

    for name_and_type in all_names_and_types:
        try:
            old_answers = set(old_resolver.query(name_and_type['name'], name_and_type['type']).rrset.to_text().splitlines())
        except Exception:
            old_answers = "EXC (old)"

        try:
            new_answers = set(new_resolver.query(name_and_type['name'], name_and_type['type']).rrset.to_text().splitlines())
        except Exception:
            new_answers = "EXC (new)"

        if old_answers == new_answers:
            #print(f"{name_and_type['name']:<30} {name_and_type['type']:<10} success")
            pass
        else:
            print(f"{name_and_type['name']:<30} {name_and_type['type']:<10} FAILURE")
            print(f"\told_answers: {old_answers}")
            print(f"\tnew_answers: {new_answers}")

    #     except Exception:
    #         import traceback; traceback.print_exc()
    #         import pdb; pdb.set_trace()
    #         print(f"{name_and_type['name']:<30} {name_and_type['type']:<10} FAILURE (exception)")
import sys
import os
import argparse
import difflib
import getpass
import keepass
import yaml
from contextlib import contextmanager
from itertools import chain
from prettytable import PrettyTable

from keepassx import clipboard
from keepassx import __version__


CONFIG_FILENAME = os.path.expanduser('~/.kpconfig')


class EntryNotFoundError(Exception):
    pass


class MultiDict(dict):
    def __setitem__(self, key, value):
        if not key in self:
            super(MultiDict, self).__setitem__(key, [])
        self.get(key).append(value)


@contextmanager
def create_db(args):
    db_file = None
    key_file = None
    if args.db_file is not None:
        db_file = os.path.expanduser(args.db_file)
    elif 'KP_DB_FILE' in os.environ:
        db_file = os.path.expanduser(os.environ['KP_DB_FILE'])
    else:
        sys.stderr.write("Must supply a db filename.\n")
        sys.exit(1)

    if args.key_file is not None:
        key_file = os.path.expanduser(args.key_file)
    elif 'KP_KEY_FILE' in os.environ:
        key_file = os.path.expanduser(os.environ['KP_KEY_FILE'])

    password = getpass.getpass('Password: ')
    with keepass.open(db_file, password=password, keyfile=key_file) as kdb:
        yield kdb


def do_list(args):
    with create_db(args) as db:
        print("Entries:\n")
        t = PrettyTable(['Title', 'User Name', 'Group'])
        t.align['Title'] = 'l'
        t.align['GroupName'] = 'l'
        if args.term is None:
            db_entries = db.obj_root.findall('.//Entry')
            entries = sorted(
                db_entries, key=lambda x: _find_string(x, 'Title').lower()
            )
        else:
            entries = _search_for_entry(db, args.term)
        for entry in entries:
            group_name = entry.getparent()['Name']
            if group_name == 'Backup':
                continue
            t.add_row([
                _find_string(entry, 'Title'),
                _find_string(entry, 'UserName'),
                group_name
            ])
        print(t)


def do_get(args):
    with create_db(args) as db:
        try:
            entries = _search_for_entry(db, args.entry_id)
        except EntryNotFoundError as e:
            sys.stderr.write(str(e))
            sys.stderr.write("\n")
            return
    t = PrettyTable(['#', 'Title', 'Username', 'URL'])
    t.align['#'] = 'r'
    t.align['Title'] = 'l'
    t.align['Username'] = 'l'
    t.align['URL'] = 'l'
    for i, entry in enumerate(entries, start=1):
        t.add_row([
            i,
            _find_string(entry, 'Title'),
            _find_string(entry, 'UserName'),
            _find_string(entry, 'URL')
        ])
    print(t)

    selected = 0
    if len(entries) > 1:
        choice = None
        while not choice:
            try:
                choice = int(raw_input('Which entry? '))
                if choice < 1 or choice > len(entries):
                    choice = None
            except KeyboardInterrupt:
                quit()
            except:
                choice = None
        selected = choice - 1

    entry = entries[selected]

    if args.clipboard_copy:
        clipboard.copy(_find_password(entry))

        if not args.quiet:
            default_fields = ['title', 'username', 'url']
            if args.entry_fields:
                fields = args.entry_fields
            else:
                fields = default_fields
            sys.stderr.write('\n')
            for field in fields:
                print("%-10s %s" % (field + ':', _find_string(entry, field)))

        sys.stderr.write("\nPassword has been copied to clipboard.\n")


def _find_password(entry):
    for s in entry.String:
        if s.Key == 'Password':
            return str(s.Value)
    return None


def _find_string(entry, key):
    for s in entry.String:
        if str(s.Key).lower() == str(key).lower():
            return str(s.Value)
    return None


def _search_for_entry(db, term):
    def fuzzy_search_by_title(title, ignore_groups=None):
        """Find an entry by by fuzzy match.

        This will check things such as:

            * case insensitive matching
            * typo checks
            * prefix matches

        If the ``ignore_groups`` argument is provided, then any matching
        entries in the ``ignore_groups`` list will not be returned.  This
        argument can be used to filter out groups you are not interested in.

        Returns a list of matches (an empty list is returned if no matches are
        found).

        """
        entries = []
        db_entries = db.obj_root.findall('.//Entry')

        # Exact matches trump
        for entry in db_entries:
            if _get_title(entry) == title:
                entries.append(entry)
        if entries:
            return _filter_entries(entries, ignore_groups)
        # Case insensitive matches next.
        title_lower = title.lower()
        for entry in db_entries:
            if _get_title(entry).lower() == title.lower():
                entries.append(entry)
        if entries:
            return _filter_entries(entries, ignore_groups)
        # Subsequence/prefix matches next.
        for entry in db_entries:
            if title_lower in _get_title(entry).lower():
                entries.append(entry)
        if entries:
            return _filter_entries(entries, ignore_groups)
        # Finally close matches that might have mispellings.
        entry_map = MultiDict()
        for entry in db_entries:
            entry_map[_get_title(entry).lower()] = entry
        matches = difflib.get_close_matches(
            title.lower(), entry_map.keys(), cutoff=0.7)
        if matches:
            return _filter_entries(
                list(
                    chain.from_iterable([entry_map[name] for name in matches])
                ),
                ignore_groups
            )
        return []

    def _get_title(entry):
        return _find_string(entry, 'Title')

    def _filter_entries(entries, ignore_groups):
        if ignore_groups is None:
            return entries
        return [entry for entry in entries if entry.getparent().Name
                not in ignore_groups]

    # Do a fuzzy match and see if we come up with anything.
    entries = fuzzy_search_by_title(term, ignore_groups=["Backup"])
    if not entries:
        raise EntryNotFoundError("Could not find an entry for: %s" % term)
    return entries


def merge_config_file_values(args):
    if os.path.isfile(CONFIG_FILENAME):
        with open(CONFIG_FILENAME, 'r') as f:
            config_data = yaml.safe_load(f)
            if not isinstance(config_data, dict):
                return
        if args.db_file is None:
            args.db_file = config_data.get('db_file')
        if args.key_file is None:
            args.key_file = config_data.get('key_file')


def create_parser():
    parser = argparse.ArgumentParser(prog='kp')
    parser.add_argument('-k', '--key-file')
    parser.add_argument('-d', '--db-file')
    parser.add_argument('--version', action='version',
                        version='%(prog)s version ' + __version__)
    subparsers = parser.add_subparsers()

    list_parser = subparsers.add_parser('list', help='List entries')
    list_parser.add_argument('term', nargs='?', help='List entries that '
                             'match the specified term.  Can be an entry id, '
                             'a uuid, or anything else supported by the "get" '
                             'command.')
    list_parser.set_defaults(run=do_list)

    get_parser = subparsers.add_parser('get', help='Get password for entry')
    get_parser.add_argument('entry_id', help='Entry name or uuid.')
    get_parser.add_argument('entry_fields', nargs='*',
                            help='Either username or password')
    get_parser.add_argument('-n', '--no-clipboard-copy', action="store_false",
                            dest="clipboard_copy", default=True,
                            help="Don't copy the password to the clipboard")
    get_parser.add_argument('-q', '--quiet', default=False,
                            action="store_true")
    get_parser.set_defaults(run=do_get)
    return parser


def _parse_args(parser, args):
    parsed_args = parser.parse_args(args=args)
    if not hasattr(parsed_args, 'run') and not args:
        # This is for python3.3 support which is different
        # from 2.x.
        # See http://bugs.python.org/issue16308
        # Rather than try to get clever, we just simulate what's suppose to
        # happen which is to print the usage, write a message to stderr and
        # exit.
        parser.print_usage()
        sys.stderr.write('kp: error: too few arguments\n')
        raise SystemExit(2)
    return parsed_args


def main(args=None):
    parser = create_parser()
    args = _parse_args(parser, args)
    merge_config_file_values(args)

    try:
        args.run(args)
    except KeyboardInterrupt:
        quit()

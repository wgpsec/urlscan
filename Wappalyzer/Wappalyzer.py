import json
import logging
import re
import warnings

import pkg_resources
from bs4 import BeautifulSoup

logger = logging.getLogger(name=__name__)


class WappalyzerError(Exception):
    """
    Raised for fatal Wappalyzer errors.
    """
    pass


class WebPage(object):
    """
    Simple representation of a web page, decoupled
    from any particular HTTP library's API.
    """

    def __init__(self, url, html, headers):
        """
        Initialize a new WebPage object.

        Parameters
        ----------

        url : str
            The web page URL.
        html : str
            The web page content (HTML)
        headers : dict
            The HTTP response headers
        """
        self.url = url
        self.html = html
        self.headers = headers

        try:
            self.headers.keys()
        except AttributeError:
            raise ValueError("Headers must be a dictionary-like object")

        self._parse_html()

    def _parse_html(self):
        """
        Parse the HTML with BeautifulSoup to find <script> and <meta> tags.
        """
        self.parsed_html = soup = BeautifulSoup(self.html, 'html.parser')
        self.scripts = [script['src'] for script in
                        soup.findAll('script', src=True)]
        self.meta = {
            meta['name'].lower():
                meta['content'] for meta in soup.findAll(
                'meta', attrs=dict(name=True, content=True))
        }

    @classmethod
    def new_from_url(cls, response):
        """
        Constructs a new WebPage object for the URL,
        using the `requests` module to fetch the HTML.

        Parameters
        ----------

        url : str
        verify: bool
        """
        try:
            response.url
        except:
            return None
        return cls.new_from_response(response)

    @classmethod
    def new_from_response(cls, response):
        """
        Constructs a new WebPage object for the response,
        using the `BeautifulSoup` module to parse the HTML.

        Parameters
        ----------

        response : requests.Response object
        """
        return cls(response.url, html=response.text, headers=response.headers)


class Wappalyzer(object):
    """
    Python Wappalyzer driver.
    """

    def __init__(self, categories, apps):
        """
        Initialize a new Wappalyzer instance.

        Parameters
        ----------

        categories : dict
            Map of category ids to names, as in apps.json.
        apps : dict
            Map of app names to app dicts, as in apps.json.
        """
        self.categories = categories
        self.apps = apps
        self.app_version = {}

        for name, app in self.apps.items():
            self._prepare_app(app)

    @classmethod
    def latest(cls, apps_file=None):
        """
        Construct a Wappalyzer instance using a apps db path passed in via
        apps_file, or alternatively the default in data/apps.json
        """
        if apps_file:
            with open(apps_file, 'r') as fd:
                obj = json.load(fd)
        else:
            obj = json.loads(pkg_resources.resource_string(__name__, "data/apps.json"))

        return cls(categories=obj['categories'], apps=obj['apps'])

    def _prepare_app(self, app):
        """
        Normalize app data, preparing it for the detection phase.
        """

        # Ensure these keys' values are lists
        for key in ['url', 'html', 'script', 'implies']:
            try:
                value = app[key]
            except KeyError:
                app[key] = []
            else:
                if not isinstance(value, list):
                    app[key] = [value]

        # Ensure these keys exist
        for key in ['headers', 'meta']:
            try:
                value = app[key]
            except KeyError:
                app[key] = {}

        # Ensure the 'meta' key is a dict
        obj = app['meta']
        if not isinstance(obj, dict):
            app['meta'] = {'generator': obj}

        # Ensure keys are lowercase
        for key in ['headers', 'meta']:
            obj = app[key]
            app[key] = {k.lower(): v for k, v in obj.items()}

        # Prepare regular expression patterns
        for key in ['url', 'html', 'script']:
            app[key] = [self._prepare_pattern(pattern) for pattern in app[key]]

        for key in ['headers', 'meta']:
            obj = app[key]
            for name, pattern in obj.items():
                obj[name] = self._prepare_pattern(obj[name])

    def _prepare_pattern(self, pattern):
        """
        Strip out key:value pairs from the pattern and compile the regular
        expression.
        """
        regex, _, rest = pattern.partition('\\;')
        # regex = pattern
        try:
            return re.compile(regex, re.I)
        except re.error as e:
            warnings.warn(
                "Caught '{error}' compiling regex: {regex}"
                    .format(error=e, regex=regex)
            )
            # regex that never matches:
            # http://stackoverflow.com/a/1845097/413622
            return re.compile(r'(?!x)x')

    def _has_app(self, app, webpage):
        """
        Determine whether the web page matches the app signature.
        """
        # Search the easiest things first and save the full-text search of the
        # HTML for last
        version = None
        for regex in app['url']:
            if regex.search(webpage.url):
                return True, version

        for name, regex in app['headers'].items():
            if name in webpage.headers:
                content = webpage.headers[name]
                if regex.search(content):
                    version = regex.findall(content)
                    # print(version)
                    return True, version

        for regex in app['script']:
            for script in webpage.scripts:
                if regex.search(script):
                    return True, version

        for name, regex in app['meta'].items():
            if name in webpage.meta:
                content = webpage.meta[name]
                if regex.search(content):
                    return True, version

        for regex in app['html']:
            if regex.search(webpage.html):
                return True, version
        return False, None

    def _get_implied_apps(self, detected_apps, versions):
        """
        Get the set of apps implied by `detected_apps`.
        """

        def __get_implied_apps(apps, version):
            _implied_apps = []
            for app in apps:
                try:
                    app_info = self.apps[app]
                    if version:
                        self.app_version[app] = version[0]

                    # print(app_info)
                    if app_info['implies']:
                        for t in app_info['implies']:
                            _dirs = {
                                "name": t,
                                "icon": self.apps[t]['icon'],
                                "website": self.apps[t]['website'],
                                "version": self.app_version[app],
                            }
                            _implied_apps.append(_dirs)
                    else:
                        # print(version)
                        _dirs = {
                            "name": app,
                            "icon": self.apps[app]['icon'],
                            "website": self.apps[app]['website'],
                            "version": self.app_version[app]
                        }
                        _implied_apps.append(_dirs)
                except KeyError:
                    pass
            _implied_apps = _implied_apps
            return _implied_apps

        implied_apps = __get_implied_apps(detected_apps, versions)
        all_implied_apps = implied_apps

        # Descend recursively until we've found all implied apps
        # while not all_implied_apps(implied_apps):
        # all_implied_apps.append(implied_apps)
        # implied_apps = __get_implied_apps(all_implied_apps)

        return all_implied_apps

    def get_categories(self, app_name):
        """
        Returns a list of the categories for an app name.
        """
        cat_nums = self.apps.get(app_name, {}).get("cats", [])
        cat_names = [self.categories.get("%s" % cat_num, "")
                     for cat_num in cat_nums]

        return cat_names

    def analyze(self, webpage):
        """
        Return a list of applications that can be detected on the web page.
        """
        _detected_apps = set()
        detected_apps = []
        for app_name, app in self.apps.items():
            is_match, version = self._has_app(app, webpage)
            if is_match:
                _detected_apps.add(app_name)
                detected_apps = self._get_implied_apps(_detected_apps, version)

        return detected_apps

    def analyze_with_categories(self, webpage):
        """
        Return a list of applications and categories that can be detected on the web page.
        """
        detected_apps = self.analyze(webpage)
        categorised_apps = {}

        for app_name in detected_apps:
            cat_names = self.get_categories(app_name)
            categorised_apps[app_name] = {"categories": cat_names}

        return categorised_apps

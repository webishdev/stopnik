import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'STOPnik',
  tagline: 'The simple and small OAuth2 | OpenId Connect server that secures applications without hassle',
  favicon: 'img/favicon.ico',

  // Set the production url of your site here
  url: 'https://stopnik.webish.dev',
  // Set the /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: '/',

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'webishdev', // Usually your GitHub org/user name.
  projectName: 'stopnik', // Usually your repo name.

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',

  // Even if you don't use internationalization, you can use this field to set
  // useful metadata like html lang. For example, if your site is Chinese, you
  // may want to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl:
            'https://github.com/webishdev/stopnik/tree/main/website',
        },
        blog: {
          showReadingTime: true,
          feedOptions: {
            type: ['rss', 'atom'],
            xslt: true,
          },
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl:
            'https://github.com/facebook/docusaurus/tree/main/packages/create-docusaurus/templates/shared/',
          // Useful options to enforce blogging best practices
          onInlineTags: 'warn',
          onInlineAuthors: 'warn',
          onUntruncatedBlogPosts: 'warn',
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    // Replace with your project's social card
    image: 'img/stopnik-social-card.jpg',
    navbar: {
      title: 'STOPnik',
      logo: {
        alt: 'STOPnik Logo',
        src: 'img/stopnik.svg',
      },
      items: [
        {
          position: 'left',
          label: 'About',
          to: 'docs/introduction/about'
        },
        {
          position: 'left',
          label: 'Getting started',
          to: 'docs/introduction/getting-started'
        },
        {
          position: 'left',
          label: 'Configuration',
          to: 'docs/introduction/config'
        },
        {
          href: 'https://github.com/webishdev/stopnik',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Documentation',
          items: [
            {
              label: 'About',
              to: 'docs/introduction/about',
            },
            {
              label: 'Getting started',
              to: 'docs/introduction/getting-started',
            },
            {
              label: 'Configuration',
              to: 'docs/introduction/config',
            },
          ],
        },
        {
          title: 'Community',
          items: [
            {
              label: 'Stack Overflow',
              href: 'https://stackoverflow.com/questions/tagged/stopnik',
            },
          ],
        },
        {
          title: 'More',
          items: [
            {
              label: 'GitHub',
              href: 'https://github.com/webishdev/stopnik',
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} STOPnik Team`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
  } satisfies Preset.ThemeConfig,
};

export default config;

import clsx from 'clsx';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

type FeatureItem = {
  title: string;
  Svg: React.ComponentType<React.ComponentProps<'svg'>>;
  description: JSX.Element;
};

const FeatureList: FeatureItem[] = [
  {
    title: 'Simple',
    Svg: require('@site/static/img/undraw_safe_re_kiil.svg').default,
    description: (
      <>
        STOPnik was primarily designed to be a straightforward and fast authorization server, minimizing code and infrastructure dependencies.
      </>
    ),
  },
  {
    title: 'Fast',
    Svg: require('@site/static/img/undraw_stars_re_6je7.svg').default,
    description: (
      <>
        STOPnik was created to learn OAuth2, OpenId Connect and Go. It leverages the built-in HTTP stack and Go channels.
      </>
    ),
  },
  {
    title: 'Cat approved',
    Svg: require('@site/static/img/undraw_playful_cat_re_ac9g.svg').default,
    description: (
      <>
          STOPnik was developed with a cat in the room, which might be considered a significant endorsement of its quality.
      </>
    ),
  },
];

function Feature({title, Svg, description}: FeatureItem) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
        <Svg className={styles.featureSvg} role="img" />
      </div>
      <div className="text--center padding-horiz--md">
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures(): JSX.Element {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}

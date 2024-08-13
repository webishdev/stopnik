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
        STOPNik was primarily designed to be a straightforward and fast authorization server, minimizing code and infrastructure dependencies.
      </>
    ),
  },
  {
    title: 'Reason',
    Svg: require('@site/static/img/undraw_click_here_re_y6uq.svg').default,
    description: (
      <>
        STOPNik was created to learn OAuth2, OpenId Connect and Go.
      </>
    ),
  },
  {
    title: 'Cat approved',
    Svg: require('@site/static/img/undraw_cat_epte.svg').default,
    description: (
      <>
          STOPNik was developed with a cat in the room, which might be considered a significant endorsement of its quality.
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

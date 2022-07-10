import utils from './utils';

/* -------------------------------------------------------------------------- */
/*                                  Count Up                                  */
/* -------------------------------------------------------------------------- */

const countupInit = () => {
  if (window.countUp) {
    const countups = document.querySelectorAll('[data-countup]');
    countups.forEach((node) => {
      const { endValue, ...options } = utils.getData(node, 'countup');

      let playCountUpTriggerd = false;
      const countUP = () =>{
        if (utils.isElementIntoView(node) && !playCountUpTriggerd) {
          const countUp = new window.countUp.CountUp(node, endValue, {
            duration: 3,
            useEasing: false,
            ...options,
          });
          if (!countUp.error) {
            countUp.start();
          } else {
            console.error(countUp.error);
          }
          playCountUpTriggerd = true;
        }
      }
      countUP();
      window.addEventListener('scroll', () =>countUP() );


    });
  }
};

export default countupInit;

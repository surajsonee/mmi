/*-----------------------------------------------
|    Draw SVG
-----------------------------------------------*/

/*
  gsap
*/
import utils from "./utils";
const Selector = {
  DATA_ZANIM_SVG_TRIGGER: 'data-zanim-svg-trigger',
  DATA_ZANIM_REPEAT: '[zanim-repeat]',
  PATH: 'path',
  ZANIM_SVG: 'zanim-svg'
}
const Events = {
  SCROLL: 'scroll',
}

const drawSvgInit = () => {

  const drawSvg = (el) => {  
    const path = el.querySelector(Selector.PATH);
    const defaultOptions = {
      delay: 0,
      duration: 2,
      ease: 'Expo.easeOut'
    };
    const controller = Object.assign(defaultOptions, utils.getData(el,Selector.ZANIM_SVG));

    const timeline = window.gsap.timeline();
    timeline.from(path, controller.duration, {
      drawSVG: 0,
      delay: controller.delay,
      ease: controller.ease,
    });
    window.gsap.set(path, { visibility: 'visible' });   
  };

  const triggerSvg =  () => {
    const svgTriggerElement = document.querySelectorAll(`[${Selector.DATA_ZANIM_SVG_TRIGGER}]`);
    svgTriggerElement.forEach( el =>{
      if( utils.isElementIntoView(el) && el.hasAttribute(Selector.DATA_ZANIM_SVG_TRIGGER) ){
        drawSvg(el);
        if(!document.querySelector(Selector.DATA_ZANIM_REPEAT)){
          el.removeAttribute(Selector.DATA_ZANIM_SVG_TRIGGER);
        }
      }
    })
  };

  triggerSvg();
  window.addEventListener(Events.SCROLL, () => triggerSvg() );

};

export default drawSvgInit;
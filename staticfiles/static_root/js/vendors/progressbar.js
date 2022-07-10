import utils from "./utils";

/* -------------------------------------------------------------------------- */
/*                               Progressbar JS                               */
/* -------------------------------------------------------------------------- */

/*
  global ProgressBar
*/
const progressBarInit = () => {
  const Selector = {
    DATA_PROGRESS_CIRCLE: '[data-progress-circle]',
    DATA_PROGRESS_LINE: '[data-progress-line]',
  }
  const Events = {
    SCROLL: 'scroll',
  }
  const { merge } = window._;

  // progressbar.js@1.0.0 version is used
  // Docs: http://progressbarjs.readthedocs.org/en/1.0.0/

  /*-----------------------------------------------
  |   Progress Circle
  -----------------------------------------------*/
  const progressCircle = document.querySelectorAll(Selector.DATA_PROGRESS_CIRCLE);
  if (progressCircle.length) {
    progressCircle.forEach((item) => {
      const userOptions = utils.getData(item, "progress-circle");

      const getDefaultOptions = () => ({
        strokeWidth: 2,
        trailWidth: 2,
        easing: "easeInOut",
        duration: 3000,
        svgStyle: {
          "stroke-linecap": "round",
          display: "block",
          width: "100%",
        },
        text: {
          autoStyleContainer: false,
        },
        from: {
          color: '#aaa',
          width: 2,
        },
        to: {
          color: '#333',
          width: 2,
        },
        // Set default step function for all animate calls
        step: (state, circle) => {
          circle.path.setAttribute('stroke', state.color);
          circle.path.setAttribute('stroke-width', state.width);

          const percentage = Math.round(circle.value() * 100);
          
          circle.setText(
            `<span class='value'>${percentage}<b>%</b></span> <span>${
              userOptions.subText || ""
            }</span>`
          );
        },
      });

      const options = merge(getDefaultOptions(), userOptions);

      const bar = new ProgressBar.Circle(item, options);

      let linearGradient = `<defs>
        <linearGradient id="gradient" x1="0%" y1="0%" x2="100%" y2="0%" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stop-color='#1970e2' />
          <stop offset="100%" stop-color='#4695ff' />
        </linearGradient>
      </defs>`;
      bar.svg.insertAdjacentHTML("beforeEnd", linearGradient);

      let playProgressTriggered = false;
      const progressCircleAnimation = () => {
        if (!playProgressTriggered) {
          if (utils.isElementIntoView(item)) {
            bar.animate(options.progress / 100);
            playProgressTriggered = true;
          }
        }
        return playProgressTriggered;
      };
      progressCircleAnimation();
      window.addEventListener(Events.SCROLL, () => {
        progressCircleAnimation();
      });

      document.body.addEventListener(
        "clickControl",
        ({ detail: { control } }) => {
          if (control === "theme") {
            bar.trail.setAttribute("stroke", utils.getGrays()["200"]);
            if (!bar.path.getAttribute("stroke").includes("url")) {
              bar.path.setAttribute("stroke", utils.getGrays()["400"]);
            }
          }
        }
      );

    });
  }

  /*-----------------------------------------------
  |   Progress Line
  -----------------------------------------------*/
  const progressLine = document.querySelectorAll(Selector.DATA_PROGRESS_LINE);
  if (progressLine.length) {
    progressLine.forEach((item) => {
      const userOptions = utils.getData(item, "progress-line");

      const getDefaultOptions = () => ({
        strokeWidth: 1,
        easing: 'easeInOut',
        duration: 3000,
        trailWidth: 1,
        color: '#333',
        svgStyle: {
          width: '100%',
          height: '0.25rem',
          'stroke-linecap': 'round',
          'border-radius': '0.125rem',
        },
        text: {
          style: { transform: null },
          autoStyleContainer: false,
        },
      
        step(state, line) {
          line.setText(`<span class='value'>${Math.round(line.value() * 100)}<b>%</b></span> <span>${userOptions.subText}</span>`);
        },
      });

      const options = merge(getDefaultOptions(), userOptions);
      const bar = new ProgressBar.Line(item, options);

      let playProgressTriggered = false;
      const progressLineAnimation = () => {
        if (!playProgressTriggered) {
          if (utils.isElementIntoView(item)) {
            bar.animate(options.progress / 100);
            playProgressTriggered = true;
          }
        }
        return playProgressTriggered;
      };
      progressLineAnimation();
      window.addEventListener(Events.SCROLL, () => {
        progressLineAnimation();
      });
    });
  }
  //----------- progress line end --------------
  
};

export default progressBarInit;

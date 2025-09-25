import { createApp } from "vue";
import PrimeVue from "primevue/config";
import { JsonTreeView } from "json-tree-view-vue3";

import "./style.css";
import "primevue/resources/themes/bootstrap4-light-blue/theme.css";

import App from "./App.vue";
import router from "./router";

import InputText from "primevue/inputtext";
import Textarea from "primevue/textarea";
import Button from "primevue/button";
import Panel from "primevue/panel";
import Card from "primevue/card";
import TabView from "primevue/tabview";
import TabPanel from "primevue/tabpanel";
import Message from "primevue/message";
import Tooltip from "primevue/tooltip";

const app = createApp(App);

app.component("TabView", TabView);
app.component("TabPanel", TabPanel);
app.component("Panel", Panel);
app.component("Button", Button);
app.component("InputText", InputText);
app.component("Textarea", Textarea);
app.component("Card", Card);
app.component("Message", Message);
app.component("Tooltip", Tooltip);

app.component("JsonTreeView", JsonTreeView);
app.directive("tooltip", Tooltip);
app.use(PrimeVue);
app.use(router).mount("#app");
